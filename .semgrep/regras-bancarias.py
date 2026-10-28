# Caminho: .semgrep/regras-bancarias.py
#
# Casos de teste das regras em .semgrep/regras-bancarias.yml.
# Convenção do "semgrep --test": um comentário "ruleid" seguido do id da
# regra indica que a linha seguinte DEVE disparar a regra; um comentário
# "ok" seguido do id indica que a linha seguinte NÃO deve dispará-la.
# Este arquivo é ignorado na varredura do repositório (.semgrepignore).
# Todos os valores são fictícios.

import hashlib
import hmac
import logging
import os
import random
import secrets
import ssl

import requests

logger = logging.getLogger(__name__)


# ------------------------------------------------ bancario-dinheiro-com-float
def dinheiro(entrada):
    # ruleid: bancario-dinheiro-com-float
    valor_transferencia = float(entrada)
    # ok: bancario-dinheiro-com-float
    valor_centavos = int(entrada)
    # ok: bancario-dinheiro-com-float
    latitude = float(entrada)
    return valor_transferencia, valor_centavos, latitude


# ruleid: bancario-dinheiro-com-float
def calcular_juros(saldo: float, taxa):
    return saldo * taxa


# --------------------------------------------- bancario-log-de-dado-sensivel
def logs(usuario, senha, token_cliente, cpf):
    # ruleid: bancario-log-de-dado-sensivel
    print(senha)
    # ruleid: bancario-log-de-dado-sensivel
    logger.info("token recebido: %s", token_cliente)
    # ruleid: bancario-log-de-dado-sensivel
    logging.warning(f"cpf do cliente {cpf}")
    # ok: bancario-log-de-dado-sensivel
    logger.info("login de %s", usuario)


def log_estruturado(log, usuario, senha):
    # ruleid: bancario-log-de-dado-sensivel
    log.evento("login", "authentication", "failure", "x", usuario=usuario, senha=senha)
    # ok: bancario-log-de-dado-sensivel
    log.evento("login", "authentication", "failure", "x", usuario=usuario)


# ------------------------------------------------ bancario-flask-debug-ativo
def subir(app):
    # ruleid: bancario-flask-debug-ativo
    app.run(host="0.0.0.0", debug=True)
    # ok: bancario-flask-debug-ativo
    app.run(host="127.0.0.1")


# --------------------------------------------------- bancario-tls-desativado
def chamar_parceiro(url):
    # ruleid: bancario-tls-desativado
    requests.post(url, json={}, verify=False, timeout=5)
    # ruleid: bancario-tls-desativado
    contexto = ssl._create_unverified_context()
    # ok: bancario-tls-desativado
    requests.post(url, json={}, timeout=5)
    return contexto


# -------------------------------------------------- bancario-sql-concatenado
def consultar_saldo(cursor, conta):
    # ruleid: bancario-sql-concatenado
    cursor.execute(f"SELECT saldo FROM contas WHERE id = '{conta}'")
    # ruleid: bancario-sql-concatenado
    cursor.execute("SELECT saldo FROM contas WHERE id = '%s'" % conta)
    # ruleid: bancario-sql-concatenado
    cursor.execute("SELECT saldo FROM contas WHERE id = " + conta)
    # ok: bancario-sql-concatenado
    cursor.execute("SELECT saldo FROM contas WHERE id = %s", (conta,))


# ----------------------------------------- bancario-segredo-com-valor-padrao
def configuracao():
    # ruleid: bancario-segredo-com-valor-padrao
    chave = os.environ.get("TOKEN_SECRET", "desenvolvimento")
    # ruleid: bancario-segredo-com-valor-padrao
    senha = os.getenv("DB_PASSWORD", "admin")
    # ok: bancario-segredo-com-valor-padrao
    porta = os.environ.get("PORTA", "8000")
    # ok: bancario-segredo-com-valor-padrao
    segredo = os.environ["TOKEN_SECRET"]
    return chave, senha, porta, segredo


# --------------------------------- bancario-comparacao-segredo-tempo-variavel
def verificar(token_recebido, esperado):
    # ruleid: bancario-comparacao-segredo-tempo-variavel
    if token_recebido == esperado:
        return True
    # ok: bancario-comparacao-segredo-tempo-variavel
    if token_recebido == None:
        return False
    # ok: bancario-comparacao-segredo-tempo-variavel
    return hmac.compare_digest(token_recebido, esperado)


# ------------------------------------------------------ bancario-hash-fraco
def resumo(dados):
    # ruleid: bancario-hash-fraco
    fraco = hashlib.md5(dados).hexdigest()
    # ok: bancario-hash-fraco
    forte = hashlib.sha256(dados).hexdigest()
    return fraco, forte


# --------------------------------------- bancario-random-em-contexto-de-seguranca
def gerar():
    # ruleid: bancario-random-em-contexto-de-seguranca
    token_reset = random.randint(100000, 999999)
    # ok: bancario-random-em-contexto-de-seguranca
    token_seguro = secrets.token_urlsafe(32)
    # ok: bancario-random-em-contexto-de-seguranca
    atraso = random.uniform(0.1, 0.5)
    return token_reset, token_seguro, atraso
