#!/usr/bin/env python3
# Caminho: siem/scripts/gerar_env.py
"""
Gera o arquivo siem/.env com segredos aleatórios e fortes.

Por que um script? Para que nenhuma senha seja escolhida "na mão", copiada
de tutorial ou versionada. Os valores são gerados com o módulo `secrets`
(CSPRNG do sistema operacional).

Uso:
    python3 siem/scripts/gerar_env.py            # cria siem/.env se não existir
    python3 siem/scripts/gerar_env.py --forcar   # sobrescreve (gera NOVAS senhas)

Observação: se o senhor sobrescrever o .env depois que o cluster já foi
criado, as senhas no volume do Elasticsearch não mudam. Nesse caso, destrua
os volumes (docker compose down -v) e suba novamente.
"""

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path

# Diretório siem/ (pai do diretório scripts/)
DIR_SIEM = Path(__file__).resolve().parent.parent
ARQUIVO_MODELO = DIR_SIEM / ".env.example"
ARQUIVO_ENV = DIR_SIEM / ".env"


def gerar_segredo(tamanho_bytes: int = 32) -> str:
    """Gera um segredo URL-safe (apenas A-Z, a-z, 0-9, '-' e '_').

    O alfabeto restrito evita problemas de escape em JSON, YAML e shell.
    """
    return secrets.token_urlsafe(tamanho_bytes)


def valores_secretos() -> dict:
    """Variáveis que recebem valores aleatórios a cada geração."""
    return {
        "ELASTIC_PASSWORD": gerar_segredo(24),
        "KIBANA_PASSWORD": gerar_segredo(24),
        "FILEBEAT_PASSWORD": gerar_segredo(24),
        "CORRELACAO_PASSWORD": gerar_segredo(24),
        "KIBANA_ENCRYPTEDSAVEDOBJECTS_KEY": gerar_segredo(48),
        "KIBANA_SECURITY_KEY": gerar_segredo(48),
        "KIBANA_REPORTING_KEY": gerar_segredo(48),
    }


def montar_conteudo() -> str:
    """Lê o .env.example linha a linha e substitui os segredos.

    Comentários e variáveis não secretas são preservados como estão;
    variáveis secretas ausentes no modelo são acrescentadas ao final.
    """
    segredos = valores_secretos()
    usados = set()
    linhas_saida = []

    for linha in ARQUIVO_MODELO.read_text(encoding="utf-8").splitlines():
        conteudo = linha.strip()
        if conteudo and not conteudo.startswith("#") and "=" in conteudo:
            chave = conteudo.split("=", 1)[0].strip()
            if chave in segredos:
                linhas_saida.append(f"{chave}={segredos[chave]}")
                usados.add(chave)
                continue
        linhas_saida.append(linha)

    faltantes = [c for c in segredos if c not in usados]
    if faltantes:
        linhas_saida.append("")
        linhas_saida.append("# Segredos adicionais gerados automaticamente")
        for chave in faltantes:
            linhas_saida.append(f"{chave}={segredos[chave]}")

    return "\n".join(linhas_saida) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera siem/.env com segredos aleatórios.")
    parser.add_argument("--forcar", action="store_true", help="sobrescreve um .env existente")
    args = parser.parse_args()

    if not ARQUIVO_MODELO.exists():
        print(f"[FALHA] Modelo não encontrado: {ARQUIVO_MODELO}", file=sys.stderr)
        return 1

    if ARQUIVO_ENV.exists() and not args.forcar:
        print(f"[AVISO] {ARQUIVO_ENV} já existe. Use --forcar para gerar novas senhas.")
        return 0

    conteudo = montar_conteudo()

    # Cria o arquivo já com permissão 600 (somente o dono lê/escreve),
    # evitando a janela em que ele existiria legível por outros usuários.
    descritor = os.open(ARQUIVO_ENV, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
        arquivo.write(conteudo)
    os.chmod(ARQUIVO_ENV, stat.S_IRUSR | stat.S_IWUSR)

    print(f"[OK] {ARQUIVO_ENV} gerado com permissão 600.")
    print("     As senhas NÃO foram exibidas. Para consultar a do usuário elastic:")
    print("     grep ^ELASTIC_PASSWORD siem/.env")
    return 0


if __name__ == "__main__":
    sys.exit(main())
