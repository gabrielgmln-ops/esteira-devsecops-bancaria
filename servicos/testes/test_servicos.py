# Caminho: servicos/testes/test_servicos.py
"""
Testes dos serviços sintéticos. Executar a partir da raiz do repositório:
    python3 -m pytest servicos/testes -q
"""

import os

import pytest

from comum.log_seguranca import LoggerSeguranca
from testes.conftest import ler_eventos


# ---------------------------------------------------------------- log ------
def test_log_recusa_campo_sensivel(tmp_path):
    log = LoggerSeguranca("teste", diretorio=str(tmp_path), saida_padrao=False)
    with pytest.raises(ValueError):
        log.evento("login", "authentication", "failure", "x", senha="nao-pode")


def test_log_formato_ecs(tmp_path):
    log = LoggerSeguranca("teste", diretorio=str(tmp_path), saida_padrao=False)
    evento = log.evento("pix_envio", "transacao", "success", "ok", usuario="cliente01", ip="198.51.100.1", valor_centavos=100)
    assert evento["event"]["action"] == "pix_envio"
    assert evento["event"]["dataset"] == "bancario.seguranca"
    assert evento["@timestamp"].endswith("Z")
    assert evento["bancario"]["valor_centavos"] == 100


def test_pseudonimo_estavel_e_nao_reversivel(tmp_path):
    log = LoggerSeguranca("teste", diretorio=str(tmp_path), saida_padrao=False)
    assert log.pseudonimo("chave@exemplo.test") == log.pseudonimo("chave@exemplo.test")
    assert "chave" not in log.pseudonimo("chave@exemplo.test")


# ------------------------------------------------------------ gateway ------
@pytest.fixture
def cliente_gateway():
    from gateway.app import app

    return app.test_client()


def test_login_sucesso_emite_token(cliente_gateway, senha_teste):
    resposta = cliente_gateway.post("/login", json={"usuario": "cliente01", "senha": senha_teste})
    assert resposta.status_code == 200
    assert resposta.get_json()["token"]


def test_login_falha_gera_evento_sem_senha(cliente_gateway):
    resposta = cliente_gateway.post(
        "/login",
        json={"usuario": "cliente02", "senha": "senha-errada-sintetica"},
        headers={"X-Forwarded-For": "203.0.113.50"},
    )
    assert resposta.status_code == 401
    ultimo = ler_eventos("gateway")[-1]
    assert ultimo["event"]["outcome"] == "failure"
    assert ultimo["event"]["reason"] == "senha_invalida"
    assert ultimo["source"]["ip"] == "203.0.113.50"
    assert "senha-errada-sintetica" not in str(ultimo)


def test_login_usuario_inexistente_mesma_resposta(cliente_gateway):
    resposta = cliente_gateway.post("/login", json={"usuario": "naoexiste", "senha": "x"})
    assert resposta.status_code == 401
    assert resposta.get_json() == {"erro": "credenciais inválidas"}


# ------------------------------------------------------------- ledger ------
def _token(usuario="cliente03"):
    from comum.autenticacao import emitir_token

    return {"Authorization": f"Bearer {emitir_token(usuario)}"}


def test_transferencia_sem_token_negada():
    from ledger.app import app

    assert app.test_client().post("/transferencias", json={}).status_code == 401


def test_transferencia_valor_float_recusado():
    from ledger.app import app

    resposta = app.test_client().post("/transferencias", json={"conta_destino": "0001-123456", "valor_centavos": 10.5}, headers=_token())
    assert resposta.status_code == 422


def test_transferencia_aprovada(monkeypatch):
    import ledger.app as ledger

    monkeypatch.setattr(ledger, "consultar_antifraude", lambda *a: {"decisao": "aprovar", "score": 10})
    resposta = ledger.app.test_client().post("/transferencias", json={"conta_destino": "0001-123456", "valor_centavos": 150000}, headers=_token())
    assert resposta.status_code == 201
    ultimo = ler_eventos("ledger")[-1]
    assert ultimo["bancario"]["valor_centavos"] == 150000
    assert "0001-123456" not in str(ultimo)  # conta pseudonimizada


def test_transferencia_falha_fechada_sem_antifraude(monkeypatch):
    import ledger.app as ledger

    # Aponta para uma porta sem serviço: o antifraude fica "indisponível".
    monkeypatch.setenv("ANTIFRAUDE_URL", "http://127.0.0.1:9")
    resposta = ledger.app.test_client().post("/transferencias", json={"conta_destino": "0001-123456", "valor_centavos": 150000}, headers=_token())
    assert resposta.status_code == 403


# ----------------------------------------------------------------- pix -----
def test_pix_chave_nao_aparece_no_log(monkeypatch):
    import pix.app as pix

    monkeypatch.setattr(pix, "consultar_antifraude", lambda *a: {"decisao": "aprovar", "score": 0})
    resposta = pix.app.test_client().post("/pix", json={"chave_destino": "chave-sintetica@exemplo.test", "valor_centavos": 5000}, headers=_token())
    assert resposta.status_code == 201
    assert "chave-sintetica@exemplo.test" not in str(ler_eventos("pix")[-1])


# ---------------------------------------------------------- antifraude -----
def test_score_puro():
    from antifraude.app import calcular_score

    assert calcular_score(1000, 1) == (0, [])
    assert calcular_score(6_000_000, 7)[0] == 70


def test_antifraude_exige_token_de_servico():
    from antifraude.app import app

    resposta = app.test_client().post("/avaliar", json={"usuario": "c", "valor_centavos": 1, "tipo": "pix"})
    assert resposta.status_code == 403


def test_antifraude_nega_valor_muito_alto_frequente():
    from antifraude.app import app

    cabecalho = {"X-Servico-Token": os.environ["SERVICO_TOKEN"]}
    cliente = app.test_client()
    resposta = None
    for _ in range(7):
        resposta = cliente.post("/avaliar", json={"usuario": "cliente09", "valor_centavos": 6_000_000, "tipo": "pix"}, headers=cabecalho)
    assert resposta.get_json()["decisao"] == "negar"
