# Caminho: servicos/comum/log_seguranca.py
"""
Log de segurança estruturado (JSON por linha, campos inspirados no ECS).

Cada serviço grava seus eventos em <LOG_DIR>/<servico>.jsonl e também no
stdout. O Filebeat (Etapa 4) lê esses arquivos e envia ao Elasticsearch.

Regras de privacidade aplicadas aqui, em um único ponto:
  - Senhas e tokens NUNCA são aceitos como campo de log.
  - Identificadores sensíveis (chave Pix, conta de destino) são
    pseudonimizados com HMAC-SHA256 antes de sair do serviço, usando a
    chave LOG_PSEUDONIMO_CHAVE. Assim o SIEM consegue correlacionar
    ("mesma chave Pix") sem conhecer o valor real.

Formato de um evento:
{
  "@timestamp": "2026-10-28T13:00:00.000Z",
  "ecs": {"version": "8.11.0"},
  "service": {"name": "gateway"},
  "event": {"dataset": "bancario.seguranca", "kind": "event",
            "category": ["authentication"], "action": "login",
            "outcome": "failure", "reason": "senha_invalida"},
  "user": {"id": "cliente07"},
  "source": {"ip": "203.0.113.10"},
  "bancario": {"valor_centavos": 1500000, ...},
  "message": "Falha de login"
}
"""

import hashlib
import hmac
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

VERSAO_ECS = "8.11.0"
DATASET = "bancario.seguranca"

# Campos que jamais podem ser registrados, mesmo por engano.
CAMPOS_PROIBIDOS = {"senha", "password", "token", "segredo", "secret", "authorization"}


def agora_iso() -> str:
    """Data/hora atual em UTC, formato ISO 8601 com milissegundos e sufixo Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def pseudonimizar(valor: str, chave: bytes) -> str:
    """HMAC-SHA256 truncado (16 hex): estável para correlação, irreversível."""
    return hmac.new(chave, valor.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


class LoggerSeguranca:
    """Grava eventos de segurança em JSON Lines de forma thread-safe."""

    def __init__(self, servico: str, diretorio: str | None = None, saida_padrao: bool = True):
        self.servico = servico
        self.saida_padrao = saida_padrao
        chave = os.environ.get("LOG_PSEUDONIMO_CHAVE")
        if not chave:
            # Falha fechada: sem chave, não há como pseudonimizar com segurança.
            raise RuntimeError("LOG_PSEUDONIMO_CHAVE não definida")
        self._chave = chave.encode("utf-8")
        base = Path(diretorio or os.environ.get("LOG_DIR", "/var/log/bancario"))
        base.mkdir(parents=True, exist_ok=True)
        self.arquivo = base / f"{servico}.jsonl"
        self._trava = threading.Lock()

    def pseudonimo(self, valor: str) -> str:
        return pseudonimizar(valor, self._chave)

    def evento(
        self,
        acao: str,
        categoria: str,
        resultado: str,
        mensagem: str,
        usuario: str | None = None,
        ip: str | None = None,
        motivo: str | None = None,
        **dados_bancarios,
    ) -> dict:
        """Monta e grava um evento. Devolve o dicionário gravado (útil em testes).

        `dados_bancarios` vira o objeto "bancario" do evento. Chaves proibidas
        geram erro imediato, para que o defeito apareça em teste, não no SIEM.
        """
        proibidas = CAMPOS_PROIBIDOS.intersection(k.lower() for k in dados_bancarios)
        if proibidas:
            raise ValueError(f"Tentativa de registrar campo sensível: {sorted(proibidas)}")

        registro = {
            "@timestamp": agora_iso(),
            "ecs": {"version": VERSAO_ECS},
            "service": {"name": self.servico},
            "event": {
                "dataset": DATASET,
                "kind": "event",
                "category": [categoria],
                "action": acao,
                "outcome": resultado,
            },
            "message": mensagem,
        }
        if motivo:
            registro["event"]["reason"] = motivo
        if usuario:
            registro["user"] = {"id": usuario}
        if ip:
            registro["source"] = {"ip": ip}
        if dados_bancarios:
            registro["bancario"] = dados_bancarios

        linha = json.dumps(registro, ensure_ascii=False, separators=(",", ":"))
        with self._trava:
            with self.arquivo.open("a", encoding="utf-8") as arquivo:
                arquivo.write(linha + "\n")
            if self.saida_padrao:
                print(linha, file=sys.stdout, flush=True)
        return registro
