# Caminho: siem/correlacao/testes/test_regras.py
"""Testes das regras de correlação, sem Elasticsearch.

Rodar: python -m pytest siem/correlacao/testes -q
"""

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RAIZ / "siem" / "correlacao"))
sys.path.insert(0, str(RAIZ / "ferramentas"))
import regras  # noqa: E402
import simulador_eventos as simulador  # noqa: E402

P = regras.carregar_parametros()
T0 = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)


def ev(minuto: float, acao: str, resultado: str = "success", **campos) -> regras.Evento:
    return regras.Evento(instante=T0 + timedelta(minutes=minuto), acao=acao, resultado=resultado, **campos)


def falhas(usuario: str, quantidade: int, inicio: float = 0, passo: float = 0.5, ip: str = "203.0.113.66"):
    return [ev(inicio + i * passo, "login", "failure", usuario=usuario, ip=ip) for i in range(quantidade)]


# ----------------------------------------------------------------- R001

def _tomada(qtd_falhas=6, valor=1_500_000, atraso_transacao=2.0):
    lista = falhas("cliente07", qtd_falhas)
    fim = qtd_falhas * 0.5
    lista.append(ev(fim, "login", usuario="cliente07", ip="203.0.113.66"))
    lista.append(ev(fim + atraso_transacao, "transferencia", usuario="cliente07", ip="203.0.113.66",
                    valor_centavos=valor, destino="abc123"))
    return lista


def test_r001_dispara_no_ataque_completo():
    alertas = regras.r001_tomada_de_conta(_tomada(), P["R001"])
    assert len(alertas) == 1
    a = alertas[0]
    assert (a.regra, a.usuario, a.valor_total_centavos, a.extras["falhas_login"]) == ("R001", "cliente07", 1_500_000, 6)
    assert a.documento()["severidade"] == "critica"


@pytest.mark.parametrize("ajuste", [
    {"qtd_falhas": 4},              # falhas abaixo do mínimo
    {"valor": 999_999},             # R$ 9.999,99: abaixo do limite
    {"atraso_transacao": 31},       # transação depois da janela de 30 min
])
def test_r001_nao_dispara_fora_dos_limites(ajuste):
    assert regras.r001_tomada_de_conta(_tomada(**ajuste), P["R001"]) == []


def test_r001_falhas_espalhadas_alem_de_10_min_nao_contam():
    lista = falhas("cliente07", 6, passo=3)  # 6 falhas em 15 min
    lista += [ev(16, "login", usuario="cliente07"), ev(17, "transferencia", usuario="cliente07", valor_centavos=2_000_000)]
    assert regras.r001_tomada_de_conta(lista, P["R001"]) == []


def test_r001_ordem_importa_transacao_antes_do_login():
    lista = [ev(0, "transferencia", usuario="cliente07", valor_centavos=2_000_000)] + falhas("cliente07", 6, inicio=1)
    lista.append(ev(5, "login", usuario="cliente07"))
    assert regras.r001_tomada_de_conta(lista, P["R001"]) == []


def test_r001_tentativa_negada_tambem_alerta():
    lista = _tomada()
    lista[-1] = ev(5, "transferencia", "failure", usuario="cliente07", valor_centavos=1_500_000)
    assert len(regras.r001_tomada_de_conta(lista, P["R001"])) == 1


# ----------------------------------------------------------------- R002

def test_r002_vinte_falhas_em_5_min_um_alerta_so():
    lista = [ev(i * 0.1, "login", "failure", usuario=f"cliente{i % 20 + 1:02d}", ip="203.0.113.99") for i in range(25)]
    alertas = regras.r002_forca_bruta_ip(lista, P["R002"])
    assert len(alertas) == 1  # rearme: 25 tentativas não viram 6 alertas
    assert len(alertas[0].extras["usuarios_alvo"]) == 20


def test_r002_dezenove_falhas_nao_disparam():
    lista = [ev(i * 0.1, "login", "failure", usuario="x", ip="203.0.113.99") for i in range(19)]
    assert regras.r002_forca_bruta_ip(lista, P["R002"]) == []


def test_r002_vinte_falhas_espalhadas_em_10_min_nao_disparam():
    lista = [ev(i * 0.5, "login", "failure", usuario="x", ip="203.0.113.99") for i in range(20)]
    assert regras.r002_forca_bruta_ip(lista, P["R002"]) == []


# ----------------------------------------------------------------- R003

def test_r003_fracionamento_dispara():
    lista = [ev(i, "pix_envio", usuario="cliente11", valor_centavos=199_000, destino=f"d{i}") for i in range(6)]
    alertas = regras.r003_fracionamento_pix(lista, P["R003"])
    assert len(alertas) == 1 and alertas[0].valor_total_centavos == 1_194_000


def test_r003_muitos_pix_pequenos_somando_pouco_nao_disparam():
    lista = [ev(i, "pix_envio", usuario="cliente11", valor_centavos=5_000, destino=f"d{i}") for i in range(10)]
    assert regras.r003_fracionamento_pix(lista, P["R003"]) == []


def test_r003_pix_negado_nao_conta():
    lista = [ev(i, "pix_envio", "failure", usuario="cliente11", valor_centavos=199_000) for i in range(6)]
    assert regras.r003_fracionamento_pix(lista, P["R003"]) == []


# ----------------------------------------------------------------- R004

def test_r004_cinco_pagadores_para_o_mesmo_destino():
    lista = [ev(i * 2, "pix_envio", usuario=f"cliente{i:02d}", valor_centavos=100_000, destino="laranja") for i in range(1, 6)]
    alertas = regras.r004_conta_laranja(lista, P["R004"])
    assert len(alertas) == 1 and alertas[0].extras["pagadores"] == [f"cliente{i:02d}" for i in range(1, 6)]


def test_r004_mesmo_pagador_repetido_nao_conta_como_varios():
    lista = [ev(i, "pix_envio", usuario="cliente01", valor_centavos=100_000, destino="laranja") for i in range(8)]
    assert regras.r004_conta_laranja(lista, P["R004"]) == []


# ----------------------------------------------------------------- gerais

def test_id_deterministico_reprocessar_nao_duplica():
    primeira = [a.id for a in regras.avaliar(_tomada(), P)]
    segunda = [a.id for a in regras.avaliar(list(reversed(_tomada())), P)]
    assert primeira == segunda and len(primeira) == 1


def test_regra_desativada_nao_roda():
    parametros = {**P, "R001": {**P["R001"], "ativa": False}}
    assert regras.avaliar(_tomada(), parametros) == []


def test_documento_do_alerta_tem_dinheiro_inteiro():
    doc = regras.avaliar(_tomada(), P)[0].documento()
    assert isinstance(doc["bancario"]["valor_total_centavos"], int)
    assert doc["event"]["kind"] == "alert"


def _simular(cenarios, semente=42):
    """Roteiro do simulador convertido em Evento, como o SIEM receberia."""
    rng = random.Random(semente)
    roteiro = simulador.montar_roteiro(cenarios, rng)
    instante = T0
    eventos = []
    for acao in roteiro:
        instante += timedelta(seconds=8)
        eventos.append(regras.Evento.de_documento(simulador.evento_simulado(acao, instante, b"chave-de-teste", rng)))
    return eventos


def test_simulador_cada_ataque_dispara_sua_regra():
    alertas = regras.avaliar(_simular(simulador.CENARIOS), P)
    assert sorted(a.regra for a in alertas) == ["R001", "R002", "R003", "R004"]


def test_simulador_trafego_normal_nao_gera_alerta():
    for semente in range(5):
        assert regras.avaliar(_simular(["normal"], semente), P) == []
