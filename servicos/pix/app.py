# Caminho: servicos/pix/app.py
"""
Pix: envio de Pix para chaves sintéticas.

Endpoints:
  POST /pix  (Bearer token)
       {"chave_destino": "chave-sintetica-42@exemplo.test", "valor_centavos": 25000}
  GET  /saude

Regras:
  - Valor em centavos inteiros, consultando o Antifraude (falha fechada).
  - A chave Pix de destino nunca é registrada em claro: só o pseudônimo
    HMAC, que permite ao SIEM detectar "muitos Pix para a mesma chave".

Eventos: pix_envio / transacao / success|failure
"""

import uuid

from flask import g, jsonify, request

from comum.autenticacao import exigir_token_cliente
from comum.log_seguranca import LoggerSeguranca
from comum.web import consultar_antifraude, corpo_json, criar_app, valor_centavos_valido

TAMANHO_MAXIMO_CHAVE = 77  # maior chave Pix válida (EVP/e-mail)

app = criar_app("pix")
log = LoggerSeguranca("pix")


@app.post("/pix")
@exigir_token_cliente
def enviar_pix():
    dados = corpo_json()
    chave = dados.get("chave_destino")
    valor = dados.get("valor_centavos")
    ip = request.remote_addr

    if not isinstance(chave, str) or not 0 < len(chave) <= TAMANHO_MAXIMO_CHAVE or not valor_centavos_valido(valor):
        log.evento("pix_envio", "transacao", "failure", "Pix com dados inválidos", usuario=g.usuario, ip=ip, motivo="dados_invalidos")
        return jsonify(erro="dados inválidos"), 422

    transacao_id = str(uuid.uuid4())
    avaliacao = consultar_antifraude(g.usuario, valor, "pix")
    comum = {
        "transacao_id": transacao_id,
        "tipo": "pix",
        "valor_centavos": valor,
        "destino_pseudonimo": log.pseudonimo(chave),
        "antifraude_score": avaliacao.get("score"),
    }

    if avaliacao.get("decisao") != "aprovar":
        log.evento("pix_envio", "transacao", "failure", "Pix negado pelo antifraude", usuario=g.usuario, ip=ip, motivo=avaliacao.get("motivo", "antifraude"), **comum)
        return jsonify(erro="pix não autorizado", transacao_id=transacao_id), 403

    log.evento("pix_envio", "transacao", "success", "Pix enviado", usuario=g.usuario, ip=ip, **comum)
    return jsonify(status="enviado", transacao_id=transacao_id), 201
