# Caminho: ci/testes/test_gate.py
"""Testes do gate de severidade com relatórios mínimos e sintéticos.

Rodar: python -m pytest ci/testes -q
"""

import json
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gate_severidade as gate  # noqa: E402

HOJE = date(2026, 10, 29)


def _trivy(*vulns):
    return {"ArtifactName": "teste", "Results": [{"Target": "x", "Vulnerabilities": list(vulns)}]}


def _vuln(cve, severidade, corrigida=""):
    return {"VulnerabilityID": cve, "PkgName": "pkg", "InstalledVersion": "1.0",
            "FixedVersion": corrigida, "Severity": severidade}


@pytest.fixture
def pasta(tmp_path):
    """Relatórios limpos; cada teste suja só o que precisa."""
    (tmp_path / "relatorio-semgrep").mkdir()
    (tmp_path / "relatorio-semgrep" / "semgrep.json").write_text(json.dumps({"results": []}))
    (tmp_path / "trivy-sca.json").write_text(json.dumps(_trivy()))
    (tmp_path / "trivy-imagem-pix.json").write_text(json.dumps(_trivy()))
    (tmp_path / "gitleaks.json").write_text("[]")
    return tmp_path


def _escrever(pasta, nome, dados):
    (pasta / nome).write_text(json.dumps(dados))


def _rodar(pasta, excecoes_yml="excecoes: []"):
    arquivo = pasta / "excecoes.yml"
    arquivo.write_text(excecoes_yml, encoding="utf-8")
    return gate.main(["--relatorios", str(pasta), "--excecoes", str(arquivo),
                      "--hoje", HOJE.isoformat()])


def test_tudo_limpo_aprova(pasta):
    assert _rodar(pasta) == 0


def test_semgrep_error_barra_e_warning_nao(pasta):
    achado = {"check_id": "regra", "path": "a.py", "start": {"line": 3},
              "extra": {"severity": "WARNING", "message": "m"}}
    _escrever(pasta / "relatorio-semgrep", "semgrep.json", {"results": [achado]})
    assert _rodar(pasta) == 0
    achado["extra"]["severity"] = "ERROR"
    _escrever(pasta / "relatorio-semgrep", "semgrep.json", {"results": [achado]})
    assert _rodar(pasta) == 1


@pytest.mark.parametrize("severidade,corrigida,esperado", [
    ("CRITICAL", "2.0", 1),
    ("HIGH", "2.0", 1),
    ("HIGH", "", 0),      # sem correção disponível: só é listado
    ("MEDIUM", "2.0", 0),
])
def test_trivy_criterio(pasta, severidade, corrigida, esperado):
    _escrever(pasta, "trivy-imagem-pix.json", _trivy(_vuln("CVE-1", severidade, corrigida)))
    assert _rodar(pasta) == esperado


def test_gitleaks_qualquer_achado_barra(pasta):
    _escrever(pasta, "gitleaks.json", [{"Fingerprint": "c:f:r:1", "File": "f", "StartLine": 1,
                                        "Commit": "abcdef123", "RuleID": "r"}])
    assert _rodar(pasta) == 1


def test_excecao_valida_libera(pasta):
    _escrever(pasta, "trivy-sca.json", _trivy(_vuln("CVE-9", "HIGH", "2.0")))
    yml = ("excecoes:\n  - ferramenta: trivy\n    id: CVE-9\n"
           "    justificativa: risco aceito por prazo curto, sem exposição\n"
           "    validade: 2026-12-31\n")
    assert _rodar(pasta, yml) == 0


def test_excecao_vencida_volta_a_barrar(pasta):
    _escrever(pasta, "trivy-sca.json", _trivy(_vuln("CVE-9", "HIGH", "2.0")))
    yml = ("excecoes:\n  - ferramenta: trivy\n    id: CVE-9\n"
           "    justificativa: risco aceito por prazo curto, sem exposição\n"
           "    validade: 2026-10-28\n")
    assert _rodar(pasta, yml) == 1


def test_excecao_com_alvo_nao_cobre_outro_alvo(pasta):
    _escrever(pasta, "trivy-sca.json", _trivy(_vuln("CVE-9", "HIGH", "2.0")))
    yml = ("excecoes:\n  - ferramenta: trivy\n    id: CVE-9\n    alvo: outra-imagem\n"
           "    justificativa: risco aceito por prazo curto, sem exposição\n"
           "    validade: 2026-12-31\n")
    assert _rodar(pasta, yml) == 1


@pytest.mark.parametrize("yml", [
    "excecoes:\n  - ferramenta: trivy\n    id: CVE-9\n    validade: 2026-12-31\n",
    "excecoes:\n  - ferramenta: trivy\n    id: CVE-9\n    justificativa: curta\n    validade: 2026-12-31\n",
    "excecoes:\n  - ferramenta: zap\n    id: X\n    justificativa: justificativa longa o bastante\n    validade: 2026-12-31\n",
    "excecoes:\n  - ferramenta: trivy\n    id: X\n    justificativa: justificativa longa o bastante\n    validade: amanha\n",
])
def test_excecao_malformada_e_erro_de_entrada(pasta, yml):
    assert _rodar(pasta, yml) == 2


def test_relatorio_ausente_e_erro_de_entrada(pasta):
    (pasta / "gitleaks.json").unlink()
    assert _rodar(pasta) == 2


def test_resumo_vai_para_step_summary(pasta, monkeypatch, tmp_path):
    destino = tmp_path / "resumo.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(destino))
    _rodar(pasta)
    assert "APROVADO" in destino.read_text(encoding="utf-8")
