# Caminho: servicos/ledger/app.py
"""
Ledger: registra transferências (TED/interna) entre contas sintéticas.

Endpoints:
  POST /transferencias  (Bearer token)
       {"conta_destino": "0001-123456", "valor_centavos": 1500000}
  GET  /saude

Regras:
  - Valor sempre em centavos inteiros (nunca float).
  - Toda transferência passa pelo Antifraude; se ele negar ou estiver
    indisponível, a transferência é recusada (falha fechada).
  - A conta de destino é pseudonimizada no log.

Eventos: transferencia / transacao / success|failure
"""

import re
import uuid

from flask import g, jsonify, request

from comum.autenticacao import exigir_token_cliente
from comum.log_seguranca import LoggerSeguranca
from comum.web import consultar_antifraude, corpo_json, criar_app, valor_centavos_valido

FORMATO_CONTA = re.compile(r"^\d{4}-\d{6}$")

app = criar_app("ledger")
log = LoggerSeguranca("ledger")


@app.post("/transferencias")
@exigir_token_cliente
def transferir():
    dados = corpo_json()
    conta_destino = dados.get("conta_destino")
    valor = dados.get("valor_centavos")
    ip = request.remote_addr

    if not isinstance(conta_destino, str) or not FORMATO_CONTA.match(conta_destino) or not valor_centavos_valido(valor):
        log.evento("transferencia", "transacao", "failure", "Transferência com dados inválidos", usuario=g.usuario, ip=ip, motivo="dados_invalidos")
        return jsonify(erro="dados inválidos"), 422

    transacao_id = str(uuid.uuid4())
    avaliacao = consultar_antifraude(g.usuario, valor, "transferencia")
    comum = {
        "transacao_id": transacao_id,
        "tipo": "transferencia",
        "valor_centavos": valor,
        "destino_pseudonimo": log.pseudonimo(conta_destino),
        "antifraude_score": avaliacao.get("score"),
    }

    if avaliacao.get("decisao") != "aprovar":
        log.evento("transferencia", "transacao", "failure", "Transferência negada pelo antifraude", usuario=g.usuario, ip=ip, motivo=avaliacao.get("motivo", "antifraude"), **comum)
        return jsonify(erro="transferência não autorizada", transacao_id=transacao_id), 403

    log.evento("transferencia", "transacao", "success", "Transferência efetivada", usuario=g.usuario, ip=ip, **comum)
    return jsonify(status="efetivada", transacao_id=transacao_id), 201
