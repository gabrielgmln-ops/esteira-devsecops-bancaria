#!/usr/bin/env python3
# Caminho: siem/correlacao/motor.py
"""
Motor de correlação do SIEM bancário (Etapa 5).

1. Busca no Elasticsearch os eventos de bancario-seguranca-* do período.
2. Roda as regras de regras.py com os parâmetros de regras.yml.
3. Grava cada alerta no índice siem-alertas com id determinístico: rodar
   de novo sobre os mesmos eventos atualiza o alerta, não duplica.

Autentica como siem_correlacao: lê os eventos e escreve SÓ em siem-alertas
(não consegue alterar a evidência). A senha vem de CORRELACAO_PASSWORD,
no ambiente ou em siem/.env; sem ela, o motor não roda.

Uso:
  python siem/correlacao/motor.py                  # uma passada, últimas 24 h
  python siem/correlacao/motor.py --desde 2h       # período menor
  python siem/correlacao/motor.py --continuo 60    # repete a cada 60 s
  python siem/correlacao/motor.py --simular        # só mostra, não grava

Uma passada examina o período inteiro: alertas que já existiam são
reescritos com o mesmo id, e só os novos aparecem como "novo".
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import regras  # noqa: E402

ARQUIVO_ENV = Path(__file__).resolve().parent.parent / ".env"
INDICE_EVENTOS = "bancario-seguranca-*"
INDICE_ALERTAS = "siem-alertas"
TAMANHO_PAGINA = 1000


class ErroElasticsearch(Exception):
    pass


class ClienteES:
    """Cliente HTTP mínimo (biblioteca padrão), com Basic Auth."""

    def __init__(self, url: str, usuario: str, senha: str):
        self.url = url.rstrip("/")
        self._auth = "Basic " + base64.b64encode(f"{usuario}:{senha}".encode()).decode()

    def chamar(self, metodo: str, caminho: str, corpo: dict | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(self.url + caminho, method=metodo,
                                     data=json.dumps(corpo).encode() if corpo is not None else None)
        req.add_header("Authorization", self._auth)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # URL do SIEM local
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as erro:
            return erro.code, json.loads(erro.read() or b"{}")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as erro:
            raise ErroElasticsearch(f"Elasticsearch inacessível em {self.url}: {erro}") from erro


def carregar_env() -> None:
    """Lê siem/.env sem sobrescrever o que já está no ambiente."""
    if ARQUIVO_ENV.exists():
        for linha in ARQUIVO_ENV.read_text(encoding="utf-8").splitlines():
            if "=" in linha and not linha.lstrip().startswith("#"):
                chave, valor = linha.split("=", 1)
                os.environ.setdefault(chave.strip(), valor.strip())


def periodo_valido(texto: str) -> str:
    """Aceita 30m, 2h, 7d (sintaxe de data math do Elasticsearch)."""
    if not re.fullmatch(r"\d{1,4}[mhd]", texto):
        raise argparse.ArgumentTypeError("use um número seguido de m, h ou d (ex.: 30m, 24h, 7d)")
    return texto


def buscar_eventos(es: ClienteES, desde: str) -> list[regras.Evento]:
    """Pagina com search_after, em ordem de horário, até o fim do período."""
    consulta = {
        "size": TAMANHO_PAGINA,
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
        "query": {"range": {"@timestamp": {"gte": f"now-{desde}"}}},
        "_source": ["@timestamp", "event", "user", "source", "bancario"],
    }
    eventos = []
    while True:
        status, corpo = es.chamar("POST", f"/{INDICE_EVENTOS}/_search", consulta)
        if status != 200:
            raise ErroElasticsearch(f"busca de eventos falhou (HTTP {status}): {corpo.get('error', corpo)}")
        hits = corpo["hits"]["hits"]
        for hit in hits:
            try:
                eventos.append(regras.Evento.de_documento(hit["_source"]))
            except (KeyError, ValueError):
                continue  # linha malformada (ex.: error.message do Filebeat)
        if len(hits) < TAMANHO_PAGINA:
            return eventos
        consulta["search_after"] = hits[-1]["sort"]


def gravar_alerta(es: ClienteES, alerta: regras.Alerta) -> bool:
    """Grava com id determinístico. Devolve True se o alerta é novo."""
    status, corpo = es.chamar("PUT", f"/{INDICE_ALERTAS}/_doc/{alerta.id}", alerta.documento())
    if status not in (200, 201):
        raise ErroElasticsearch(f"gravação do alerta {alerta.id} falhou (HTTP {status}): {corpo.get('error', corpo)}")
    return corpo.get("result") == "created"


def uma_passada(es: ClienteES, parametros: dict, desde: str, simular: bool) -> int:
    eventos = buscar_eventos(es, desde)
    alertas = regras.avaliar(eventos, parametros)
    print(f"[motor] {len(eventos)} eventos nas últimas {desde}; {len(alertas)} alerta(s).")
    for alerta in alertas:
        situacao = "simulado" if simular else ("NOVO" if gravar_alerta(es, alerta) else "já registrado")
        print(f"  [{alerta.severidade.upper():<7}] {alerta.regra} {alerta.id[:8]} ({situacao}): {alerta.mensagem}")
    return len(alertas)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Motor de correlação do SIEM bancário.")
    parser.add_argument("--desde", type=periodo_valido, default="24h", help="período analisado (padrão: 24h)")
    parser.add_argument("--continuo", type=int, metavar="SEGUNDOS", help="repete a cada N segundos")
    parser.add_argument("--simular", action="store_true", help="mostra os alertas sem gravar")
    args = parser.parse_args(argv)

    carregar_env()
    senha = os.environ.get("CORRELACAO_PASSWORD")
    if not senha:
        print("[ERRO] CORRELACAO_PASSWORD ausente (rode scripts/gerar_env.py).", file=sys.stderr)
        return 1
    es_url = os.environ.get("ES_URL", f"http://127.0.0.1:{os.environ.get('ES_PORT', '9200')}")
    es = ClienteES(es_url, "siem_correlacao", senha)
    parametros = regras.carregar_parametros()

    try:
        while True:
            uma_passada(es, parametros, args.desde, args.simular)
            if not args.continuo:
                return 0
            time.sleep(args.continuo)
    except ErroElasticsearch as erro:
        print(f"[ERRO] {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
