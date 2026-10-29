#!/usr/bin/env python3
# Caminho: scripts/gerar_env.py
"""
Gera os arquivos .env do projeto com segredos aleatórios e fortes.

Para cada modelo listado em MODELOS (ex.: siem/.env.example), cria o .env
correspondente (ex.: siem/.env). Toda variável cujo valor no modelo seja
o marcador "defina-pelo-gerar_env" recebe um segredo novo; as demais são
copiadas como estão.

Se a mesma variável secreta aparecer em mais de um modelo, ela recebe o
MESMO valor em todos os arquivos (segredo compartilhado).

Os marcadores "auto-uid" e "auto-gid" são trocados pelo UID/GID do
usuário atual, para que os contêineres gravem em logs/ com o dono certo.

Por que um script? Para que nenhuma senha seja escolhida "na mão", copiada
de tutorial ou versionada. Os valores vêm do módulo `secrets` (CSPRNG).

Uso:
    python3 scripts/gerar_env.py            # cria os .env que ainda não existem
    python3 scripts/gerar_env.py --forcar   # recria todos (gera NOVAS senhas)

Atenção: depois que o Elasticsearch foi criado, trocar a ELASTIC_PASSWORD
no .env não altera a senha gravada no volume. Ao usar --forcar, recrie o
SIEM com: (cd siem && docker compose down -v && docker compose up -d)
"""

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
MARCADOR = "defina-pelo-gerar_env"

# Modelos (.env.example) a processar, relativos à raiz do repositório.
MODELOS = [RAIZ / "siem" / ".env.example", RAIZ / "servicos" / ".env.example"]


def _id_usuario(marcador: str) -> int:
    """UID/GID do usuário atual. No Windows não existe getuid: o Docker
    Desktop já mapeia as permissões do volume, então usamos 1000."""
    # O hasattr vem antes: ler os.getuid no Windows já levanta AttributeError.
    if not hasattr(os, "getuid"):
        return 1000
    return os.getuid() if marcador == "auto-uid" else os.getgid()


def gerar_segredo() -> str:
    """43 caracteres URL-safe (A-Z, a-z, 0-9, '-', '_'): sem problemas de escape."""
    return secrets.token_urlsafe(32)


def processar(modelo: Path, compartilhados: dict) -> str:
    """Devolve o conteúdo do .env a partir do modelo, preenchendo os marcadores."""
    saida = []
    for linha in modelo.read_text(encoding="utf-8").splitlines():
        conteudo = linha.strip()
        if conteudo and not conteudo.startswith("#") and "=" in conteudo:
            chave, valor = (parte.strip() for parte in conteudo.split("=", 1))
            if valor in ("auto-uid", "auto-gid"):
                saida.append(f"{chave}={_id_usuario(valor)}")
                continue
            if valor == MARCADOR:
                if chave not in compartilhados:
                    compartilhados[chave] = gerar_segredo()
                saida.append(f"{chave}={compartilhados[chave]}")
                continue
        saida.append(linha)
    return "\n".join(saida) + "\n"


def ler_existentes(arquivo: Path, compartilhados: dict) -> None:
    """Reaproveita segredos de um .env já existente (mantém valores comuns iguais)."""
    for linha in arquivo.read_text(encoding="utf-8").splitlines():
        if "=" in linha and not linha.lstrip().startswith("#"):
            chave, valor = (parte.strip() for parte in linha.split("=", 1))
            compartilhados.setdefault(chave, valor)


def gravar_privado(arquivo: Path, conteudo: str) -> None:
    """Cria o arquivo já com permissão 600 (somente o dono lê/escreve)."""
    descritor = os.open(arquivo, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descritor, "w", encoding="utf-8") as saida:
        saida.write(conteudo)
    os.chmod(arquivo, stat.S_IRUSR | stat.S_IWUSR)


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera os arquivos .env com segredos aleatórios.")
    parser.add_argument("--forcar", action="store_true", help="recria todos os .env (novas senhas)")
    args = parser.parse_args()

    compartilhados: dict = {}

    # Sem --forcar, segredos já existentes são preservados e reaproveitados.
    if not args.forcar:
        for modelo in MODELOS:
            destino = modelo.with_name(".env")
            if destino.exists():
                ler_existentes(destino, compartilhados)

    for modelo in MODELOS:
        if not modelo.exists():
            print(f"[AVISO] Modelo ausente, ignorado: {modelo.relative_to(RAIZ)}")
            continue
        destino = modelo.with_name(".env")
        if destino.exists() and not args.forcar:
            # Acrescenta apenas variáveis novas que surgiram no modelo.
            existentes = {l.split("=", 1)[0].strip() for l in destino.read_text(encoding="utf-8").splitlines() if "=" in l and not l.lstrip().startswith("#")}
            novas = [l for l in processar(modelo, compartilhados).splitlines() if "=" in l and not l.lstrip().startswith("#") and l.split("=", 1)[0].strip() not in existentes]
            if novas:
                gravar_privado(destino, destino.read_text(encoding="utf-8").rstrip("\n") + "\n\n# Acrescentadas automaticamente\n" + "\n".join(novas) + "\n")
                print(f"[OK] {destino.relative_to(RAIZ)} atualizado com {len(novas)} variável(is) nova(s).")
            else:
                print(f"[OK] {destino.relative_to(RAIZ)} já existe e está completo.")
            continue
        gravar_privado(destino, processar(modelo, compartilhados))
        print(f"[OK] {destino.relative_to(RAIZ)} gerado com permissão 600.")

    print("Os segredos não foram exibidos. Ex.: grep ^ELASTIC_PASSWORD siem/.env")
    return 0


if __name__ == "__main__":
    sys.exit(main())
