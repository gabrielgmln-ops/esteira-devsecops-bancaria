# Caminho: servicos/testes/conftest.py
"""
Configuração dos testes: define variáveis de ambiente SINTÉTICAS antes de
importar os serviços (eles exigem segredos na inicialização) e direciona
os logs para um diretório temporário.
"""

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

import pytest

# Permite "import comum", "import gateway" etc. a partir de servicos/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DIR_LOGS_TESTE = tempfile.mkdtemp(prefix="logs-teste-")
SENHA_TESTE = secrets.token_urlsafe(16)

os.environ.update(
    {
        "LOG_DIR": DIR_LOGS_TESTE,
        "TOKEN_SECRET": secrets.token_urlsafe(32),
        "SERVICO_TOKEN": secrets.token_urlsafe(32),
        "SENHA_USUARIOS_SINTETICOS": SENHA_TESTE,
        "LOG_PSEUDONIMO_CHAVE": secrets.token_urlsafe(32),
        "CONFIAR_PROXY": "1",
    }
)


def ler_eventos(servico: str) -> list[dict]:
    """Lê todos os eventos gravados por um serviço durante os testes."""
    arquivo = Path(DIR_LOGS_TESTE) / f"{servico}.jsonl"
    if not arquivo.exists():
        return []
    return [json.loads(linha) for linha in arquivo.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def senha_teste() -> str:
    return SENHA_TESTE
