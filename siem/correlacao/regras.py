# Caminho: siem/correlacao/regras.py
"""
Regras de correlação do SIEM bancário (Etapa 5), como funções PURAS.

Cada regra recebe a lista de eventos (já ordenada por horário) e os seus
parâmetros de regras.yml, e devolve uma lista de Alerta. Não há acesso a
rede nem ao Elasticsearch aqui: tudo é testável com eventos montados à mão
(siem/correlacao/testes/).

Regras:
  R001  tomada de conta: falhas de login -> login ok -> transação alta
  R002  força bruta / credential stuffing por IP
  R003  fracionamento de Pix
  R004  possível conta laranja (muitos pagadores para o mesmo destino)

Janela deslizante com "rearme": depois de um alerta, a janela é esvaziada,
e um novo alerta da mesma chave só sai com eventos NOVOS suficientes. Assim,
um ataque de 25 tentativas gera 1 alerta, não 6.

Id determinístico: hash(regra, chave, início da janela). Reprocessar os
mesmos eventos gera os mesmos ids, e o índice siem-alertas não duplica.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

ARQUIVO_REGRAS = Path(__file__).resolve().parent / "regras.yml"
MAXIMO_EVIDENCIAS = 30  # eventos guardados por alerta (o resto só conta)


@dataclass(frozen=True)
class Evento:
    """Recorte de um evento ECS com o que as regras usam."""
    instante: datetime
    acao: str
    resultado: str
    usuario: str | None = None
    ip: str | None = None
    valor_centavos: int | None = None
    destino: str | None = None
    transacao_id: str | None = None

    @classmethod
    def de_documento(cls, doc: dict) -> "Evento":
        """Converte o _source do Elasticsearch (ou uma linha do JSONL)."""
        bancario = doc.get("bancario") or {}
        return cls(
            instante=datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00")),
            acao=doc["event"]["action"],
            resultado=doc["event"].get("outcome", ""),
            usuario=(doc.get("user") or {}).get("id"),
            ip=(doc.get("source") or {}).get("ip"),
            valor_centavos=bancario.get("valor_centavos"),
            destino=bancario.get("destino_pseudonimo"),
            transacao_id=bancario.get("transacao_id"),
        )

    def resumo(self) -> dict:
        """Evidência gravada no alerta (sem nada além do que já está no log)."""
        dados = {"@timestamp": self.instante.isoformat().replace("+00:00", "Z"),
                 "acao": self.acao, "resultado": self.resultado}
        for nome in ("usuario", "ip", "valor_centavos", "destino", "transacao_id"):
            if getattr(self, nome) is not None:
                dados[nome] = getattr(self, nome)
        return dados


@dataclass
class Alerta:
    regra: str
    nome: str
    severidade: str
    chave: str  # o que se repete no ataque: usuário, IP ou destino
    mensagem: str
    eventos: list[Evento]
    usuario: str | None = None
    ip: str | None = None
    destino: str | None = None
    valor_total_centavos: int | None = None
    extras: dict = field(default_factory=dict)

    @property
    def inicio(self) -> datetime:
        return self.eventos[0].instante

    @property
    def fim(self) -> datetime:
        return self.eventos[-1].instante

    @property
    def id(self) -> str:
        base = f"{self.regra}|{self.chave}|{self.inicio.isoformat()}"
        return hashlib.sha256(base.encode()).hexdigest()[:24]

    def documento(self) -> dict:
        """Documento do índice siem-alertas (campos no padrão ECS onde há)."""
        doc = {
            "@timestamp": self.fim.isoformat().replace("+00:00", "Z"),
            "event": {"kind": "alert", "dataset": "bancario.alertas", "severity_label": self.severidade},
            "regra": {"id": self.regra, "nome": self.nome},
            "severidade": self.severidade,
            "message": self.mensagem,
            "janela": {"inicio": self.inicio.isoformat().replace("+00:00", "Z"),
                       "fim": self.fim.isoformat().replace("+00:00", "Z")},
            "quantidade_eventos": len(self.eventos),
            "evidencias": [e.resumo() for e in self.eventos[:MAXIMO_EVIDENCIAS]],
        }
        if self.usuario:
            doc["user"] = {"id": self.usuario}
        if self.ip:
            doc["source"] = {"ip": self.ip}
        bancario = {}
        if self.destino:
            bancario["destino_pseudonimo"] = self.destino
        if self.valor_total_centavos is not None:
            bancario["valor_total_centavos"] = self.valor_total_centavos
        if bancario:
            doc["bancario"] = bancario
        doc.update(self.extras)
        return doc


def carregar_parametros(arquivo: Path = ARQUIVO_REGRAS) -> dict:
    return yaml.safe_load(arquivo.read_text(encoding="utf-8"))["regras"]


def _reais(centavos: int) -> str:
    """Formata centavos como R$ 1.234,56 (só para mensagens)."""
    inteiro, resto = divmod(centavos, 100)
    return f"R$ {inteiro:,}".replace(",", ".") + f",{resto:02d}"


def _por_chave(eventos, filtro, chave):
    grupos = defaultdict(list)
    for e in eventos:
        if filtro(e) and chave(e):
            grupos[chave(e)].append(e)
    return grupos


# ---------------------------------------------------------------------------
# R001 - tomada de conta
# ---------------------------------------------------------------------------

def r001_tomada_de_conta(eventos: list[Evento], p: dict) -> list[Alerta]:
    janela_falhas = timedelta(minutes=p["janela_falhas_min"])
    janela_transacao = timedelta(minutes=p["janela_transacao_min"])
    alertas = []
    relevantes = _por_chave(eventos, lambda e: e.acao in ("login", "transferencia", "pix_envio"), lambda e: e.usuario)

    for usuario, lista in relevantes.items():
        falhas: deque[Evento] = deque()
        armado: list[Evento] | None = None  # falhas + login ok, à espera da transação

        for e in lista:
            if e.acao == "login" and e.resultado == "failure":
                falhas.append(e)
            elif e.acao == "login" and e.resultado == "success":
                while falhas and e.instante - falhas[0].instante > janela_falhas:
                    falhas.popleft()
                if len(falhas) >= p["falhas_minimas"]:
                    armado = [*falhas, e]
                falhas.clear()
            elif armado and e.instante - armado[-1].instante <= janela_transacao:
                # Qualquer resultado conta: uma tentativa negada também é ataque.
                if (e.valor_centavos or 0) >= p["valor_minimo_centavos"]:
                    qtd_falhas = len(armado) - 1
                    alertas.append(Alerta(
                        regra="R001", nome=p["nome"], severidade=p["severidade"], chave=usuario,
                        usuario=usuario, ip=e.ip, destino=e.destino,
                        valor_total_centavos=e.valor_centavos,
                        mensagem=(f"{qtd_falhas} falhas de login de {usuario}, login com sucesso e "
                                  f"{e.acao} de {_reais(e.valor_centavos)} ({e.resultado})"),
                        eventos=[*armado, e],
                        extras={"falhas_login": qtd_falhas},
                    ))
                    armado = None
            elif armado:
                armado = None  # passou a janela de 30 min sem transação alta
    return alertas


# ---------------------------------------------------------------------------
# R002 - força bruta por IP
# ---------------------------------------------------------------------------

def r002_forca_bruta_ip(eventos: list[Evento], p: dict) -> list[Alerta]:
    janela = timedelta(minutes=p["janela_min"])
    alertas = []
    falhas = _por_chave(eventos, lambda e: e.acao == "login" and e.resultado == "failure", lambda e: e.ip)

    for ip, lista in falhas.items():
        janela_atual: deque[Evento] = deque()
        for e in lista:
            janela_atual.append(e)
            while e.instante - janela_atual[0].instante > janela:
                janela_atual.popleft()
            if len(janela_atual) >= p["falhas_minimas"]:
                usuarios = sorted({x.usuario for x in janela_atual if x.usuario})
                alertas.append(Alerta(
                    regra="R002", nome=p["nome"], severidade=p["severidade"], chave=ip, ip=ip,
                    mensagem=f"{len(janela_atual)} falhas de login do IP {ip} contra {len(usuarios)} usuário(s)",
                    eventos=list(janela_atual),
                    extras={"usuarios_alvo": usuarios},
                ))
                janela_atual.clear()  # rearme
    return alertas


# ---------------------------------------------------------------------------
# R003 - fracionamento de Pix
# ---------------------------------------------------------------------------

def r003_fracionamento_pix(eventos: list[Evento], p: dict) -> list[Alerta]:
    janela = timedelta(minutes=p["janela_min"])
    alertas = []
    pix = _por_chave(eventos, lambda e: e.acao == "pix_envio" and e.resultado == "success", lambda e: e.usuario)

    for usuario, lista in pix.items():
        janela_atual: deque[Evento] = deque()
        for e in lista:
            janela_atual.append(e)
            while e.instante - janela_atual[0].instante > janela:
                janela_atual.popleft()
            soma = sum(x.valor_centavos or 0 for x in janela_atual)
            if len(janela_atual) >= p["quantidade_minima"] and soma >= p["soma_minima_centavos"]:
                alertas.append(Alerta(
                    regra="R003", nome=p["nome"], severidade=p["severidade"], chave=usuario,
                    usuario=usuario, valor_total_centavos=soma,
                    mensagem=f"{len(janela_atual)} Pix de {usuario} somando {_reais(soma)} em até {p['janela_min']} min",
                    eventos=list(janela_atual),
                ))
                janela_atual.clear()
    return alertas


# ---------------------------------------------------------------------------
# R004 - conta laranja
# ---------------------------------------------------------------------------

def r004_conta_laranja(eventos: list[Evento], p: dict) -> list[Alerta]:
    janela = timedelta(minutes=p["janela_min"])
    alertas = []
    pix = _por_chave(eventos, lambda e: e.acao == "pix_envio" and e.resultado == "success", lambda e: e.destino)

    for destino, lista in pix.items():
        janela_atual: deque[Evento] = deque()
        for e in lista:
            janela_atual.append(e)
            while e.instante - janela_atual[0].instante > janela:
                janela_atual.popleft()
            pagadores = sorted({x.usuario for x in janela_atual if x.usuario})
            if len(pagadores) >= p["usuarios_distintos_minimos"]:
                soma = sum(x.valor_centavos or 0 for x in janela_atual)
                alertas.append(Alerta(
                    regra="R004", nome=p["nome"], severidade=p["severidade"], chave=destino,
                    destino=destino, valor_total_centavos=soma,
                    mensagem=f"{len(pagadores)} usuários enviaram {_reais(soma)} via Pix ao destino {destino}",
                    eventos=list(janela_atual),
                    extras={"pagadores": pagadores},
                ))
                janela_atual.clear()
    return alertas


REGRAS = {
    "R001": r001_tomada_de_conta,
    "R002": r002_forca_bruta_ip,
    "R003": r003_fracionamento_pix,
    "R004": r004_conta_laranja,
}


def avaliar(eventos: list[Evento], parametros: dict) -> list[Alerta]:
    """Roda todas as regras ativas sobre os eventos (ordenados aqui)."""
    ordenados = sorted(eventos, key=lambda e: e.instante)
    alertas = []
    for regra_id, funcao in REGRAS.items():
        p = parametros.get(regra_id)
        if p and p.get("ativa", True):
            alertas += funcao(ordenados, p)
    return sorted(alertas, key=lambda a: a.fim)
