#!/usr/bin/env python3
# Caminho: siem/kibana/provisionar_painel.py
"""
Provisiona no Kibana o painel "SIEM Bancário" (Etapa 6), pela API.

Cria (ou atualiza, se já existirem):
  - data views: bancario-seguranca-* (eventos) e siem-alertas (alertas);
  - 7 visualizações e 1 busca salva;
  - o dashboard "SIEM Bancário", com intervalo padrão das últimas 24 h.

Todos os objetos têm ids fixos e são gravados com overwrite: rodar de novo
atualiza o painel em vez de criar cópias (idempotente, como o setup.sh).

As visualizações são do editor clássico (agg-based), descritas em JSON:
assim o painel inteiro fica versionado neste arquivo, revisável em PR.

Uso (com o SIEM no ar):
  python siem/kibana/provisionar_painel.py
A senha do elastic vem de ELASTIC_PASSWORD, no ambiente ou em siem/.env.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ARQUIVO_ENV = Path(__file__).resolve().parent.parent / ".env"
VERSAO = "8.17.4"

DV_EVENTOS = "dv-bancario-seguranca"
DV_ALERTAS = "dv-siem-alertas"
DASHBOARD = "siem-bancario"

FILTRO_FALHA_LOGIN = 'event.action : "login" and event.outcome : "failure"'


# ---------------------------------------------------------------------------
# Peças das visualizações (formato do editor clássico do Kibana)
# ---------------------------------------------------------------------------

def _contagem() -> dict:
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def _termos(id_: str, campo: str, schema: str, tamanho: int = 10, rotulo: str | None = None) -> dict:
    params = {"field": campo, "size": tamanho, "order": "desc", "orderBy": "1",
              "otherBucket": False, "missingBucket": False}
    if rotulo:
        params["customLabel"] = rotulo
    return {"id": id_, "enabled": True, "type": "terms", "schema": schema, "params": params}


def _tempo(id_: str = "2") -> dict:
    return {"id": id_, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}}


def _params_barras(titulo_eixo: str) -> dict:
    return {
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                          "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100},
                          "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                       "show": True, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                       "title": {"text": titulo_eixo}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": titulo_eixo, "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
        "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
    }


def _params_tabela() -> dict:
    return {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
            "showTotal": False, "totalFunc": "sum", "percentageCol": ""}


def _params_pizza() -> dict:
    return {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}


def _params_metrica() -> dict:
    return {"addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                       "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                       "labels": {"show": True}, "invertColors": False,
                       "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                 "subText": "", "fontSize": 48}}}


def visualizacao(id_: str, titulo: str, tipo: str, params: dict, aggs: list, data_view: str,
                 consulta: str = "") -> dict:
    """Objeto salvo do tipo visualization, ligado a um data view por referência."""
    fonte = {"query": {"query": consulta, "language": "kuery"}, "filter": [],
             "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    return {
        "type": "visualization", "id": id_,
        "attributes": {
            "title": titulo,
            "visState": json.dumps({"title": titulo, "type": tipo, "params": params, "aggs": aggs}),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(fonte)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": data_view}],
    }


def objetos_do_painel() -> list[dict]:
    """Lista de objetos salvos, na ordem em que aparecem no dashboard."""
    vis = [
        visualizacao("vis-alertas-total", "Alertas no período", "metric", _params_metrica(),
                     [_contagem()], DV_ALERTAS),
        visualizacao("vis-alertas-por-regra", "Alertas por regra", "pie", _params_pizza(),
                     [_contagem(), _termos("2", "regra.id", "segment")], DV_ALERTAS),
        visualizacao("vis-alertas-por-severidade", "Alertas por severidade", "pie", _params_pizza(),
                     [_contagem(), _termos("2", "severidade", "segment")], DV_ALERTAS),
        visualizacao("vis-alertas-linha-do-tempo", "Linha do tempo dos alertas", "histogram",
                     _params_barras("Alertas"),
                     [_contagem(), _tempo(), _termos("3", "severidade", "group")], DV_ALERTAS),
        visualizacao("vis-falhas-login-tempo", "Falhas de login ao longo do tempo", "histogram",
                     _params_barras("Falhas de login"),
                     [_contagem(), _tempo(), _termos("3", "event.reason", "group")],
                     DV_EVENTOS, FILTRO_FALHA_LOGIN),
        visualizacao("vis-top-usuarios-alertas", "Usuários com mais alertas", "table", _params_tabela(),
                     [_contagem(), _termos("2", "user.id", "bucket", rotulo="Usuário")], DV_ALERTAS),
        visualizacao("vis-top-ips-falhas", "IPs com mais falhas de login", "table", _params_tabela(),
                     [_contagem(), _termos("2", "source.ip", "bucket", rotulo="IP de origem")],
                     DV_EVENTOS, FILTRO_FALHA_LOGIN),
    ]
    busca = {
        "type": "search", "id": "busca-ultimos-alertas",
        "attributes": {
            "title": "Últimos alertas",
            "columns": ["severidade", "regra.id", "message", "user.id", "source.ip"],
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": "", "language": "kuery"}, "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": DV_ALERTAS}],
    }

    # Grade de 48 colunas do Kibana: (largura, altura) de cada painel.
    tamanhos = [(8, 10), (14, 10), (14, 10), (12, 10),
                (24, 12), (24, 12), (16, 12), (16, 12), (48, 14)]
    paineis, referencias, x, y, altura_linha = [], [], 0, 0, 0
    for indice, (objeto, (w, h)) in enumerate(zip(vis + [busca], tamanhos), start=1):
        if x + w > 48:
            x, y, altura_linha = 0, y + altura_linha, 0
        paineis.append({"version": VERSAO, "type": objeto["type"], "panelIndex": str(indice),
                        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(indice)},
                        "embeddableConfig": {}, "panelRefName": f"panel_{indice}"})
        referencias.append({"name": f"panel_{indice}", "type": objeto["type"], "id": objeto["id"]})
        x, altura_linha = x + w, max(altura_linha, h)

    painel = {
        "type": "dashboard", "id": DASHBOARD,
        "attributes": {
            "title": "SIEM Bancário",
            "description": "Alertas de correlação (R001 a R004) e eventos de segurança da plataforma bancária sintética.",
            "panelsJSON": json.dumps(paineis),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": referencias,
    }
    return vis + [busca, painel]


# ---------------------------------------------------------------------------
# API do Kibana
# ---------------------------------------------------------------------------

def carregar_env() -> None:
    if ARQUIVO_ENV.exists():
        for linha in ARQUIVO_ENV.read_text(encoding="utf-8").splitlines():
            if "=" in linha and not linha.lstrip().startswith("#"):
                chave, valor = linha.split("=", 1)
                os.environ.setdefault(chave.strip(), valor.strip())


def chamar(kibana: str, auth: str, metodo: str, caminho: str, corpo) -> tuple[int, dict | list]:
    req = urllib.request.Request(kibana + caminho, method=metodo, data=json.dumps(corpo).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    req.add_header("kbn-xsrf", "provisionar_painel")  # exigido pelo Kibana em escrita
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # Kibana local
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as erro:
        return erro.code, json.loads(erro.read() or b"{}")


def main() -> int:
    carregar_env()
    senha = os.environ.get("ELASTIC_PASSWORD")
    if not senha:
        print("[ERRO] ELASTIC_PASSWORD ausente (rode scripts/gerar_env.py).", file=sys.stderr)
        return 1
    kibana = os.environ.get("KIBANA_URL", f"http://127.0.0.1:{os.environ.get('KIBANA_PORT', '5601')}")
    auth = "Basic " + base64.b64encode(f"elastic:{senha}".encode()).decode()

    try:
        for id_, titulo, padrao in [(DV_EVENTOS, "Eventos de segurança", "bancario-seguranca-*"),
                                    (DV_ALERTAS, "Alertas do SIEM", "siem-alertas")]:
            status, corpo = chamar(kibana, auth, "POST", "/api/data_views/data_view", {
                "override": True,
                "data_view": {"id": id_, "name": titulo, "title": padrao, "timeFieldName": "@timestamp"}})
            if status != 200:
                print(f"[ERRO] data view {padrao}: HTTP {status} {corpo}", file=sys.stderr)
                return 1
            print(f"[OK] data view {padrao}")

        objetos = objetos_do_painel()
        status, corpo = chamar(kibana, auth, "POST", "/api/saved_objects/_bulk_create?overwrite=true", objetos)
        erros = [o for o in (corpo.get("saved_objects", []) if isinstance(corpo, dict) else []) if "error" in o]
        if status != 200 or erros:
            print(f"[ERRO] objetos salvos: HTTP {status} {erros or corpo}", file=sys.stderr)
            return 1
        print(f"[OK] {len(objetos) - 1} painéis e o dashboard 'SIEM Bancário'")
    except urllib.error.URLError as erro:
        print(f"[ERRO] Kibana inacessível em {kibana}: {erro}", file=sys.stderr)
        return 1

    print(f"\nAbra: {kibana}/app/dashboards#/view/{DASHBOARD}  (usuário: elastic)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
