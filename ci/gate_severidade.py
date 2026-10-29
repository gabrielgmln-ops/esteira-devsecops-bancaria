# Caminho: ci/gate_severidade.py
"""Gate de severidade da esteira DevSecOps (Etapa 3).

Lê os relatórios JSON dos scanners, normaliza os achados num formato único,
aplica as exceções de ci/excecoes.yml e decide se o merge é barrado.

Critério (o mesmo para todo o projeto):
  - Semgrep: severidade ERROR barra.
  - Trivy (dependências e imagens): HIGH ou CRITICAL COM correção disponível
    barra. Sem correção, o time não tem o que fazer; o achado só é listado.
  - Gitleaks: qualquer achado barra.

Uma exceção só vale se tiver justificativa e validade no futuro. Exceção
vencida não protege nada: o achado volta a barrar, para forçar a revisão.

Uso:
  python ci/gate_severidade.py --relatorios relatorios --excecoes ci/excecoes.yml

Saída: 0 se nada barra; 1 se algo barra; 2 se a entrada for inválida
(relatório faltando ou exceção malformada). No GitHub Actions, o resumo vai
também para $GITHUB_STEP_SUMMARY.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

SEVERIDADES_TRIVY_ALTAS = {"HIGH", "CRITICAL"}
FERRAMENTAS = {"semgrep", "trivy", "gitleaks"}


class EntradaInvalida(Exception):
    """Relatório ou arquivo de exceções em formato inesperado."""


@dataclass
class Achado:
    ferramenta: str
    id: str  # o que uma exceção precisa citar para cobrir o achado
    severidade: str
    alvo: str  # arquivo, pacote ou imagem
    descricao: str
    barra: bool  # se, sem exceção, este achado barra o merge
    excecao: dict | None = None


@dataclass
class Excecao:
    ferramenta: str
    id: str
    justificativa: str
    validade: date
    alvo: str | None = None  # opcional: restringe a exceção a um alvo
    usada: bool = False

    def cobre(self, achado: Achado) -> bool:
        if self.ferramenta != achado.ferramenta or self.id != achado.id:
            return False
        return self.alvo is None or self.alvo in achado.alvo


# ---------------------------------------------------------------------------
# Leitura dos relatórios
# ---------------------------------------------------------------------------

def _ler_json(caminho: Path):
    if not caminho.is_file():
        raise EntradaInvalida(f"relatório ausente: {caminho}")
    try:
        return json.loads(caminho.read_text(encoding="utf-8"))
    except json.JSONDecodeError as erro:
        raise EntradaInvalida(f"JSON inválido em {caminho}: {erro}") from erro


def ler_semgrep(caminho: Path) -> list[Achado]:
    dados = _ler_json(caminho)
    achados = []
    for r in dados.get("results", []):
        severidade = r["extra"]["severity"]
        achados.append(Achado(
            ferramenta="semgrep",
            id=r["check_id"],
            severidade=severidade,
            alvo=f'{r["path"]}:{r["start"]["line"]}',
            descricao=(r["extra"].get("message", "").splitlines() or [""])[0][:120],
            barra=severidade == "ERROR",
        ))
    return achados


def ler_trivy(caminho: Path) -> list[Achado]:
    dados = _ler_json(caminho)
    # Nome do relatório (ex.: trivy-imagem-pix) como origem: o ArtifactName
    # aponta para o .tar temporário, que não diz nada a quem lê o resumo.
    origem = caminho.stem
    achados = []
    for resultado in dados.get("Results") or []:
        for v in resultado.get("Vulnerabilities") or []:
            corrigida = v.get("FixedVersion") or ""
            achados.append(Achado(
                ferramenta="trivy",
                id=v["VulnerabilityID"],
                severidade=v["Severity"],
                alvo=f'{origem} > {v["PkgName"]} {v["InstalledVersion"]}',
                descricao=f'corrigido em {corrigida}' if corrigida else "sem correção",
                barra=v["Severity"] in SEVERIDADES_TRIVY_ALTAS and bool(corrigida),
            ))
    return achados


def ler_gitleaks(caminho: Path) -> list[Achado]:
    dados = _ler_json(caminho) or []
    # O relatório já vem com --redact: nenhum campo aqui contém o segredo.
    return [Achado(
        ferramenta="gitleaks",
        id=a["Fingerprint"],
        severidade="SEGREDO",
        alvo=f'{a["File"]}:{a["StartLine"]} ({a["Commit"][:7]})',
        descricao=a["RuleID"],
        barra=True,
    ) for a in dados]


def coletar(pasta: Path) -> list[Achado]:
    """Procura os relatórios em qualquer subpasta (cada artefato baixado
    vira uma pasta). Semgrep, SCA e Gitleaks são obrigatórios: se faltarem,
    o gate não pode afirmar que está tudo limpo."""
    def unico(nome: str) -> Path:
        encontrados = sorted(pasta.rglob(nome))
        if not encontrados:
            raise EntradaInvalida(f"relatório ausente: {nome} em {pasta}")
        return encontrados[0]

    achados = ler_semgrep(unico("semgrep.json"))
    achados += ler_trivy(unico("trivy-sca.json"))
    imagens = sorted(pasta.rglob("trivy-imagem-*.json"))
    if not imagens:
        raise EntradaInvalida(f"nenhum relatório trivy-imagem-*.json em {pasta}")
    for caminho in imagens:
        achados += ler_trivy(caminho)
    achados += ler_gitleaks(unico("gitleaks.json"))
    return achados


# ---------------------------------------------------------------------------
# Exceções
# ---------------------------------------------------------------------------

def ler_excecoes(caminho: Path) -> list[Excecao]:
    if not caminho.is_file():
        return []
    conteudo = yaml.safe_load(caminho.read_text(encoding="utf-8")) or {}
    excecoes = []
    for i, item in enumerate(conteudo.get("excecoes") or [], start=1):
        faltando = {"ferramenta", "id", "justificativa", "validade"} - set(item)
        if faltando:
            raise EntradaInvalida(f"exceção {i}: faltam os campos {sorted(faltando)}")
        if item["ferramenta"] not in FERRAMENTAS:
            raise EntradaInvalida(f"exceção {i}: ferramenta desconhecida {item['ferramenta']!r}")
        if len(str(item["justificativa"]).strip()) < 20:
            raise EntradaInvalida(f"exceção {i}: justificativa curta demais (mínimo de 20 caracteres)")
        validade = item["validade"]
        if not isinstance(validade, date):
            raise EntradaInvalida(f"exceção {i}: validade deve ser uma data AAAA-MM-DD")
        excecoes.append(Excecao(
            ferramenta=item["ferramenta"],
            id=str(item["id"]),
            justificativa=str(item["justificativa"]).strip(),
            validade=validade,
            alvo=item.get("alvo"),
        ))
    return excecoes


def aplicar_excecoes(achados: list[Achado], excecoes: list[Excecao], hoje: date) -> list[str]:
    """Marca os achados cobertos por exceção válida. Devolve avisos sobre
    exceções vencidas e exceções que não cobriram nada (lixo a remover)."""
    avisos = []
    for achado in achados:
        for exc in excecoes:
            if exc.cobre(achado):
                exc.usada = True
                if exc.validade >= hoje:
                    achado.excecao = {"justificativa": exc.justificativa,
                                      "validade": exc.validade.isoformat()}
                break
    for exc in excecoes:
        if exc.validade < hoje:
            avisos.append(f"Exceção VENCIDA em {exc.validade}: {exc.ferramenta} {exc.id}")
        elif not exc.usada:
            avisos.append(f"Exceção sem uso (pode ser removida): {exc.ferramenta} {exc.id}")
    return avisos


# ---------------------------------------------------------------------------
# Decisão e relatório
# ---------------------------------------------------------------------------

def bloqueantes(achados: list[Achado]) -> list[Achado]:
    return [a for a in achados if a.barra and a.excecao is None]


def montar_resumo(achados: list[Achado], avisos: list[str]) -> str:
    barram = bloqueantes(achados)
    excecionados = [a for a in achados if a.barra and a.excecao]
    linhas = ["## Gate de severidade", ""]
    if barram:
        linhas.append(f"**BARRADO**: {len(barram)} achado(s) de severidade alta.")
    else:
        linhas.append("**APROVADO**: nenhum achado de severidade alta sem exceção.")
    linhas += ["", "| Ferramenta | Total | Barram | Com exceção |", "|---|---|---|---|"]
    for ferramenta in ("semgrep", "trivy", "gitleaks"):
        da = [a for a in achados if a.ferramenta == ferramenta]
        linhas.append(f"| {ferramenta} | {len(da)} "
                      f"| {sum(1 for a in barram if a.ferramenta == ferramenta)} "
                      f"| {sum(1 for a in excecionados if a.ferramenta == ferramenta)} |")
    if barram:
        linhas += ["", "### Achados que barram", "",
                   "| Ferramenta | Severidade | ID | Onde | Detalhe |", "|---|---|---|---|---|"]
        linhas += [f"| {a.ferramenta} | {a.severidade} | `{a.id}` | {a.alvo} | {a.descricao} |"
                   for a in barram]
    if excecionados:
        linhas += ["", "### Aceitos por exceção", ""]
        linhas += [f"- {a.ferramenta} `{a.id}` em {a.alvo}: válida até "
                   f"{a.excecao['validade']} ({a.excecao['justificativa']})" for a in excecionados]
    if avisos:
        linhas += ["", "### Avisos", ""] + [f"- {aviso}" for aviso in avisos]
    return "\n".join(linhas) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--relatorios", type=Path, default=Path("relatorios"))
    parser.add_argument("--excecoes", type=Path, default=Path("ci/excecoes.yml"))
    parser.add_argument("--hoje", type=date.fromisoformat, default=date.today(),
                        help="data de referência (só para testes)")
    args = parser.parse_args(argv)

    try:
        achados = coletar(args.relatorios)
        avisos = aplicar_excecoes(achados, ler_excecoes(args.excecoes), args.hoje)
    except (EntradaInvalida, KeyError, yaml.YAMLError) as erro:
        print(f"[ERRO] entrada inválida para o gate: {erro}", file=sys.stderr)
        return 2

    resumo = montar_resumo(achados, avisos)
    print(resumo)
    destino = os.environ.get("GITHUB_STEP_SUMMARY")
    if destino:
        with open(destino, "a", encoding="utf-8") as arquivo:
            arquivo.write(resumo)
    return 1 if bloqueantes(achados) else 0


if __name__ == "__main__":
    sys.exit(main())
