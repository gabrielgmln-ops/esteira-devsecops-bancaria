# Caminho: servicos/comum/autenticacao.py
"""
Autenticação entre cliente e serviços, e entre serviços.

- Token de cliente: emitido pelo Gateway após login, assinado com
  TOKEN_SECRET (itsdangerous, HMAC-SHA256) e com validade limitada.
- Token de serviço: segredo compartilhado SERVICO_TOKEN, enviado no
  cabeçalho X-Servico-Token nas chamadas Ledger/Pix -> Antifraude e
  comparado em tempo constante.

Nenhum segredo possui valor padrão: se a variável não existir, o serviço
não sobe (falha fechada).
"""

import hmac
import os
from functools import wraps

from flask import abort, g, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

VALIDADE_TOKEN_SEGUNDOS = 15 * 60
_SAL = "bancario-token-cliente"


def segredo_obrigatorio(nome: str) -> str:
    """Lê um segredo do ambiente; aborta a inicialização se ausente ou curto."""
    valor = os.environ.get(nome)
    if not valor or len(valor) < 16:
        raise RuntimeError(f"Variável de ambiente {nome} ausente ou curta demais (mínimo 16 caracteres)")
    return valor


def _serializador() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(segredo_obrigatorio("TOKEN_SECRET"), salt=_SAL)


def emitir_token(usuario: str) -> str:
    """Gera um token assinado contendo apenas o identificador do usuário."""
    return _serializador().dumps({"sub": usuario})


def validar_token(token: str) -> str | None:
    """Devolve o usuário do token ou None se inválido/expirado."""
    try:
        dados = _serializador().loads(token, max_age=VALIDADE_TOKEN_SEGUNDOS)
    except (BadSignature, SignatureExpired):
        return None
    return dados.get("sub") if isinstance(dados, dict) else None


def exigir_token_cliente(funcao):
    """Decorador Flask: exige 'Authorization: Bearer <token>' válido.

    Em caso de sucesso, disponibiliza o usuário em flask.g.usuario.
    """

    @wraps(funcao)
    def envoltorio(*args, **kwargs):
        cabecalho = request.headers.get("Authorization", "")
        if not cabecalho.startswith("Bearer "):
            abort(401)
        usuario = validar_token(cabecalho.removeprefix("Bearer ").strip())
        if usuario is None:
            abort(401)
        g.usuario = usuario
        return funcao(*args, **kwargs)

    return envoltorio


def exigir_token_servico(funcao):
    """Decorador Flask: exige X-Servico-Token igual a SERVICO_TOKEN."""

    @wraps(funcao)
    def envoltorio(*args, **kwargs):
        esperado = segredo_obrigatorio("SERVICO_TOKEN")
        recebido = request.headers.get("X-Servico-Token", "")
        # compare_digest evita ataques de temporização.
        if not hmac.compare_digest(recebido.encode(), esperado.encode()):
            abort(403)
        return funcao(*args, **kwargs)

    return envoltorio
