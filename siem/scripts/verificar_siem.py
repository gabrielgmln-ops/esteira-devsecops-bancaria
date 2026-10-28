#!/usr/bin/env python3
# Caminho: siem/scripts/verificar_siem.py
"""
Verificação de saúde do SIEM local.

Checagens:
  1. Elasticsearch exige autenticação (requisição anônima => HTTP 401).
  2. Elasticsearch responde ao usuário elastic com status green/yellow.
  3. Usuário kibana_system autentica (senha definida pelo setup).
  4. Kibana está "available".

Usa apenas a biblioteca padrão do Python (sem dependências a instalar).
As senhas vêm de variáveis de ambiente; se ausentes, são lidas de siem/.env.

Uso:
    python3 siem/scripts/verificar_siem.py
Código de saída: 0 se tudo OK, 1 se alguma checagem falhar.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ARQUIVO_ENV = Path(__file__).resolve().parent.parent / ".env"


def carregar_env() -> None:
    """Carrega siem/.env em os.environ sem sobrescrever variáveis já definidas."""
    if not ARQUIVO_ENV.exists():
        return
    for linha in ARQUIVO_ENV.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        chave, valor = linha.split("=", 1)
        os.environ.setdefault(chave.strip(), valor.strip())


def requisicao(url: str, usuario: str | None = None, senha: str | None = None):
    """Faz um GET e devolve (status_http, corpo_json_ou_None)."""
    req = urllib.request.Request(url, method="GET")
    if usuario is not None:
        token = base64.b64encode(f"{usuario}:{senha}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            corpo = resp.read().decode()
            return resp.status, json.loads(corpo) if corpo else None
    except urllib.error.HTTPError as erro:
        return erro.code, None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as erro:
        return 0, {"erro": str(erro)}


def main() -> int:
    carregar_env()
    es_url = os.environ.get("ES_URL", f"http://127.0.0.1:{os.environ.get('ES_PORT', '9200')}")
    kb_url = os.environ.get("KIBANA_URL", f"http://127.0.0.1:{os.environ.get('KIBANA_PORT', '5601')}")
    senha_elastic = os.environ.get("ELASTIC_PASSWORD")
    senha_kibana = os.environ.get("KIBANA_PASSWORD")

    if not senha_elastic or not senha_kibana:
        print("[FALHA] ELASTIC_PASSWORD/KIBANA_PASSWORD ausentes (gere com siem/scripts/gerar_env.py).")
        return 1

    resultados = []

    # 1. Acesso anônimo deve ser negado.
    status, _ = requisicao(f"{es_url}/")
    resultados.append(("Elasticsearch exige autenticação (anônimo => 401)", status == 401, f"HTTP {status}"))

    # 2. Saúde do cluster.
    status, corpo = requisicao(f"{es_url}/_cluster/health", "elastic", senha_elastic)
    saude = (corpo or {}).get("status", "desconhecido")
    resultados.append(("Cluster Elasticsearch saudável", status == 200 and saude in ("green", "yellow"), f"status={saude}"))

    # 3. kibana_system autentica.
    status, corpo = requisicao(f"{es_url}/_security/_authenticate", "kibana_system", senha_kibana)
    resultados.append(("Usuário kibana_system autentica", status == 200, f"HTTP {status}"))

    # 4. Kibana disponível.
    status, corpo = requisicao(f"{kb_url}/api/status", "elastic", senha_elastic)
    nivel = (((corpo or {}).get("status") or {}).get("overall") or {}).get("level", "desconhecido")
    versao = ((corpo or {}).get("version") or {}).get("number", "?")
    resultados.append(("Kibana disponível", status == 200 and nivel == "available", f"nível={nivel} versão={versao}"))

    falhas = 0
    for descricao, ok, detalhe in resultados:
        print(f"[{'OK' if ok else 'FALHA'}] {descricao} ({detalhe})")
        falhas += 0 if ok else 1

    if falhas:
        print(f"\n{falhas} checagem(ns) falharam. Veja: docker compose logs es01 setup kibana")
        return 1
    print("\nSIEM local operacional. Kibana: " + kb_url + " (usuário: elastic)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
