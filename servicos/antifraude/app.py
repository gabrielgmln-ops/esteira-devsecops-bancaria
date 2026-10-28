# Caminho: servicos/antifraude/app.py
"""
Antifraude: avalia o risco de uma transação e decide aprovar/negar.

Endpoint (somente serviço-a-serviço, exige X-Servico-Token):
  POST /avaliar {"usuario": "cliente07", "valor_centavos": 1500000, "tipo": "pix"}
       -> {"decisao": "aprovar"|"negar", "score": 0..100, "motivo": "..."}

Modelo DIDÁTICO e propositalmente simples (pontuação por regras):
  +40 valor >= R$ 50.000,00
  +20 valor >= R$ 10.000,00
  +30 mais de 5 transações do mesmo usuário nos últimos 10 minutos
  Nega quando score >= LIMIAR_NEGACAO.

O antifraude é a defesa em linha; o SIEM (Etapa 5) é a defesa de
correlação, que enxerga padrões entre serviços (ex.: força bruta no
Gateway seguida de transferência no Ledger).

Eventos: avaliacao_antifraude / transacao / success (aprovou) | failure (negou)
"""

import threading
import time
from collections import defaultdict, deque

from flask import jsonify

from comum.autenticacao import exigir_token_servico
from comum.log_seguranca import LoggerSeguranca
from comum.web import corpo_json, criar_app, valor_centavos_valido

LIMIAR_NEGACAO = 70
JANELA_SEGUNDOS = 600
TIPOS_VALIDOS = {"pix", "transferencia"}

app = criar_app("antifraude")
log = LoggerSeguranca("antifraude")

# Histórico recente por usuário (em memória; suficiente para o laboratório).
_historico: dict[str, deque] = defaultdict(deque)
_trava = threading.Lock()


def calcular_score(valor_centavos: int, transacoes_recentes: int) -> tuple[int, list[str]]:
    """Função pura de pontuação, fácil de testar."""
    score, motivos = 0, []
    if valor_centavos >= 5_000_000:
        score += 40
        motivos.append("valor_muito_alto")
    elif valor_centavos >= 1_000_000:
        score += 20
        motivos.append("valor_alto")
    if transacoes_recentes > 5:
        score += 30
        motivos.append("alta_frequencia")
    return min(score, 100), motivos


@app.post("/avaliar")
@exigir_token_servico
def avaliar():
    dados = corpo_json()
    usuario = dados.get("usuario")
    valor = dados.get("valor_centavos")
    tipo = dados.get("tipo")

    if not isinstance(usuario, str) or not usuario or tipo not in TIPOS_VALIDOS or not valor_centavos_valido(valor):
        return jsonify(decisao="negar", score=100, motivo="dados_invalidos"), 422

    agora = time.monotonic()
    with _trava:
        fila = _historico[usuario]
        while fila and agora - fila[0] > JANELA_SEGUNDOS:
            fila.popleft()
        fila.append(agora)
        recentes = len(fila)

    score, motivos = calcular_score(valor, recentes)
    decisao = "negar" if score >= LIMIAR_NEGACAO else "aprovar"
    motivo = ",".join(motivos) or "sem_risco"

    log.evento(
        "avaliacao_antifraude",
        "transacao",
        "success" if decisao == "aprovar" else "failure",
        f"Antifraude decidiu {decisao}",
        usuario=usuario,
        motivo=motivo,
        tipo=tipo,
        valor_centavos=valor,
        antifraude_score=score,
    )
    return jsonify(decisao=decisao, score=score, motivo=motivo)
