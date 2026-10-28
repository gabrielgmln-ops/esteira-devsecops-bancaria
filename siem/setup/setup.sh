#!/usr/bin/env bash
# Caminho: siem/setup/setup.sh
#
# Script de inicialização do SIEM, executado UMA vez pelo contêiner "setup"
# do docker-compose, logo após o Elasticsearch ficar saudável.
#
# Responsabilidades (Etapa 0):
#   1. Aguardar o Elasticsearch responder com autenticação.
#   2. Definir a senha do usuário interno kibana_system.
#
# É idempotente: pode ser executado várias vezes sem efeito colateral.
# Todas as senhas chegam por variável de ambiente (nunca por argumento fixo).

set -euo pipefail

ES_URL="${ES_URL:-http://es01:9200}"

# Confere se as variáveis obrigatórias existem antes de qualquer coisa.
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD não definida}"
: "${KIBANA_PASSWORD:?KIBANA_PASSWORD não definida}"

log() { echo "[setup] $(date -u +%H:%M:%S) $*"; }

# Chamada autenticada ao Elasticsearch como superusuário.
# Uso: es MÉTODO CAMINHO [CORPO_JSON]
# A senha é passada via arquivo de configuração do curl lido do stdin (-K -),
# para não aparecer na lista de processos (ps) do contêiner.
es() {
  local metodo="$1" caminho="$2" corpo="${3:-}"
  local args=(-sS -X "$metodo" "${ES_URL}${caminho}" -H "Content-Type: application/json" -K -)
  if [[ -n "$corpo" ]]; then
    args+=(-d "$corpo")
  fi
  printf 'user = "elastic:%s"\n' "$ELASTIC_PASSWORD" | curl "${args[@]}"
}

log "Aguardando o Elasticsearch em ${ES_URL}..."
until es GET "/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  sleep 3
done
log "Elasticsearch disponível."

log "Definindo a senha do usuário kibana_system..."
until es POST "/_security/user/kibana_system/_password" \
  "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q '^{}'; do
  sleep 3
done
log "Senha do kibana_system definida."

log "Setup concluído com sucesso."
