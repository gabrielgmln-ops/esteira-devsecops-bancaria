# Caminho: servicos/comum/web.py
"""
Utilidades web compartilhadas: criação da app Flask com padrões seguros,
leitura validada de JSON e chamada ao serviço Antifraude.
"""

import json
import os
import urllib.error
import urllib.request

from flask import Flask, current_app, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from comum.autenticacao import segredo_obrigatorio

# Limite de valor por operação no laboratório: R$ 1.000.000,00 (em centavos).
VALOR_MAXIMO_CENTAVOS = 100_000_000


def _cabecalhos_seguranca(resposta):
    """Cabeçalhos HTTP defensivos aplicados a toda resposta."""
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    resposta.headers["Cache-Control"] = "no-store"
    resposta.headers["Content-Security-Policy"] = "default-src 'none'"
    return resposta


def _erro_json(erro):
    """Erros em JSON com mensagem genérica: não vaza detalhes internos."""
    return jsonify(erro=getattr(erro, "name", "erro")), getattr(erro, "code", 400)


def _saude():
    return jsonify(status="ok", servico=current_app.name)


def criar_app(nome: str) -> Flask:
    """Cria a app Flask com cabeçalhos de segurança e tratamento de erro JSON."""
    app = Flask(nome)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # corpo máximo de 16 KiB
    app.json.sort_keys = False

    # Só confia em X-Forwarded-For quando explicitamente habilitado
    # (necessário no laboratório para o simulador variar o IP de origem).
    if os.environ.get("CONFIAR_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

    app.after_request(_cabecalhos_seguranca)
    for codigo in (400, 401, 403, 404, 405, 413, 422):
        app.register_error_handler(codigo, _erro_json)
    app.add_url_rule("/saude", "saude", _saude, methods=["GET"])
    return app


def corpo_json() -> dict:
    """Lê o corpo JSON da requisição; devolve {} se ausente ou inválido."""
    dados = request.get_json(silent=True)
    return dados if isinstance(dados, dict) else {}


def valor_centavos_valido(valor) -> bool:
    """Dinheiro é sempre inteiro em centavos (nunca float) e dentro do limite."""
    return isinstance(valor, int) and not isinstance(valor, bool) and 0 < valor <= VALOR_MAXIMO_CENTAVOS


def consultar_antifraude(usuario: str, valor_centavos: int, tipo: str) -> dict:
    """Consulta o Antifraude. Falha FECHADA: indisponível => operação negada."""
    url = os.environ.get("ANTIFRAUDE_URL", "http://antifraude:8000") + "/avaliar"
    corpo = json.dumps({"usuario": usuario, "valor_centavos": valor_centavos, "tipo": tipo}).encode()
    req = urllib.request.Request(
        url,
        data=corpo,
        method="POST",
        headers={"Content-Type": "application/json", "X-Servico-Token": segredo_obrigatorio("SERVICO_TOKEN")},
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resposta:  # URL interna definida por configuração
            return json.loads(resposta.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {"decisao": "negar", "score": 100, "motivo": "antifraude_indisponivel"}
