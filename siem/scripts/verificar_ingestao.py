#!/usr/bin/env python3
# Caminho: siem/scripts/verificar_ingestao.py
"""
Verificação da ingestão de logs no SIEM (Etapa 4).

Checagens:
  1. Existem eventos nos índices bancario-seguranca-* (Filebeat funcionando).
  2. Os campos críticos chegaram com o tipo certo (valor em long, IP em ip).
  3. Menor privilégio: filebeat_writer NÃO consegue ler os eventos.
  4. Menor privilégio: siem_correlacao NÃO consegue gravar nos eventos
     (a evidência não pode ser alterada pelo motor de correlação).
  5. siem_correlacao consegue ler os eventos (o que a Etapa 5 precisa).

Mostra também a contagem de eventos por ação e resultado.

Uso:
    python siem/scripts/verificar_ingestao.py
Código de saída: 0 se tudo OK, 1 se alguma checagem falhar.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

# Mesma leitura do siem/.env usada pela verificação de saúde.
from verificar_siem import carregar_env

INDICE = "bancario-seguranca-*"


def chamar(metodo: str, url: str, usuario: str, senha: str, corpo: dict | None = None):
    """Devolve (status_http, corpo_json_ou_None)."""
    dados = json.dumps(corpo).encode() if corpo is not None else None
    req = urllib.request.Request(url, data=dados, method=metodo)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{usuario}:{senha}".encode()).decode())
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # URL local do laboratório
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as erro:
        return erro.code, None
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return 0, None


def main() -> int:
    carregar_env()
    es = os.environ.get("ES_URL", f"http://127.0.0.1:{os.environ.get('ES_PORT', '9200')}")
    # Falha fechada: sem senha não há verificação (nada de senha vazia).
    faltando = [v for v in ("ELASTIC_PASSWORD", "FILEBEAT_PASSWORD", "CORRELACAO_PASSWORD") if not os.environ.get(v)]
    if faltando:
        print(f"[FALHA] Variáveis ausentes: {', '.join(faltando)} (rode scripts/gerar_env.py).")
        return 1
    admin = ("elastic", os.environ["ELASTIC_PASSWORD"])
    filebeat = ("filebeat_writer", os.environ["FILEBEAT_PASSWORD"])
    correlacao = ("siem_correlacao", os.environ["CORRELACAO_PASSWORD"])
    resultados = []

    # 1. Há eventos?
    status, corpo = chamar("GET", f"{es}/{INDICE}/_count", *admin)
    total = (corpo or {}).get("count", 0)
    resultados.append(("Eventos ingeridos em " + INDICE, status == 200 and total > 0, f"{total} documentos"))

    # 2. Tipos dos campos críticos (vindos do index template, não do acaso).
    status, corpo = chamar("GET", f"{es}/{INDICE}/_mapping/field/bancario.valor_centavos,source.ip", *admin)
    tipos = set()
    for indice in (corpo or {}).values():
        for nome, campo in indice.get("mappings", {}).items():
            tipos.add((nome, next(iter(campo["mapping"].values()))["type"]))
    esperado = {("bancario.valor_centavos", "long"), ("source.ip", "ip")}
    resultados.append(("Mapeamento: valor em long e IP em ip", esperado <= tipos, str(sorted(tipos))))

    # 3. filebeat_writer não lê.
    status, _ = chamar("GET", f"{es}/{INDICE}/_search?size=1", *filebeat)
    resultados.append(("filebeat_writer NÃO lê eventos", status == 403, f"HTTP {status}"))

    # 4. siem_correlacao não grava nos eventos.
    status, _ = chamar("POST", f"{es}/bancario-seguranca-teste/_doc", *correlacao, corpo={"message": "adulteracao"})
    resultados.append(("siem_correlacao NÃO grava em eventos", status == 403, f"HTTP {status}"))

    # 5. siem_correlacao lê.
    status, _ = chamar("GET", f"{es}/{INDICE}/_search?size=1", *correlacao)
    resultados.append(("siem_correlacao lê eventos", status == 200, f"HTTP {status}"))

    falhas = 0
    for descricao, ok, detalhe in resultados:
        print(f"[{'OK' if ok else 'FALHA'}] {descricao} ({detalhe})")
        falhas += 0 if ok else 1

    # Panorama por ação/resultado, para conferência visual.
    consulta = {"size": 0, "aggs": {"acao": {"terms": {"field": "event.action"},
                "aggs": {"resultado": {"terms": {"field": "event.outcome"}}}}}}
    status, corpo = chamar("POST", f"{es}/{INDICE}/_search", *admin, corpo=consulta)
    if status == 200:
        print("\nEventos por ação:")
        for balde in corpo["aggregations"]["acao"]["buckets"]:
            detalhes = ", ".join(f"{b['key']}={b['doc_count']}" for b in balde["resultado"]["buckets"])
            print(f"  {balde['key']:<22} {balde['doc_count']:>5}  ({detalhes})")

    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
