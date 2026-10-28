# Caminho: servicos/gateway/app.py
"""
Gateway: porta de entrada da plataforma. Autentica clientes e emite tokens.

Endpoints:
  POST /login  {"usuario": "cliente07", "senha": "..."}  -> {"token": "..."}
  GET  /saude

Usuários SINTÉTICOS: cliente01..cliente20, todos com a senha definida em
SENHA_USUARIOS_SINTETICOS (variável de ambiente). As senhas são guardadas
apenas como hash (PBKDF2/scrypt do Werkzeug).

Eventos de segurança gerados:
  login / authentication / success|failure  (motivo: senha_invalida,
  usuario_inexistente, requisicao_invalida)
"""

import secrets

from flask import jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from comum.autenticacao import emitir_token, segredo_obrigatorio
from comum.log_seguranca import LoggerSeguranca
from comum.web import corpo_json, criar_app

QUANTIDADE_USUARIOS = 20

app = criar_app("gateway")
log = LoggerSeguranca("gateway")

# Base de usuários sintéticos em memória: {usuario: hash_da_senha}.
_hash_senha = generate_password_hash(segredo_obrigatorio("SENHA_USUARIOS_SINTETICOS"))
USUARIOS = {f"cliente{n:02d}": _hash_senha for n in range(1, QUANTIDADE_USUARIOS + 1)}

# Hash fictício usado quando o usuário não existe, para que o tempo de
# resposta seja parecido e não revele quais usuários existem.
_HASH_FICTICIO = generate_password_hash(secrets.token_urlsafe(32))


@app.post("/login")
def login():
    dados = corpo_json()
    usuario = dados.get("usuario")
    senha = dados.get("senha")
    ip = request.remote_addr

    if not isinstance(usuario, str) or not isinstance(senha, str) or not usuario or len(usuario) > 64:
        log.evento("login", "authentication", "failure", "Requisição de login inválida", ip=ip, motivo="requisicao_invalida")
        return jsonify(erro="credenciais inválidas"), 401

    hash_cadastrado = USUARIOS.get(usuario)
    senha_confere = check_password_hash(hash_cadastrado or _HASH_FICTICIO, senha)

    if hash_cadastrado is None or not senha_confere:
        motivo = "usuario_inexistente" if hash_cadastrado is None else "senha_invalida"
        log.evento("login", "authentication", "failure", "Falha de login", usuario=usuario, ip=ip, motivo=motivo)
        # Mesma resposta nos dois casos (não revela se o usuário existe).
        return jsonify(erro="credenciais inválidas"), 401

    log.evento("login", "authentication", "success", "Login bem-sucedido", usuario=usuario, ip=ip)
    return jsonify(token=emitir_token(usuario))
