#!/usr/bin/env bash
# Caminho: siem/setup/setup.sh
#
# Script de inicialização do SIEM, executado UMA vez pelo contêiner "setup"
# do docker-compose, logo após o Elasticsearch ficar saudável.
#
# Responsabilidades:
#   1. Aguardar o Elasticsearch responder com autenticação.          (Etapa 0)
#   2. Definir a senha do usuário interno kibana_system.             (Etapa 0)
#   3. Criar o index template dos eventos bancario-seguranca-*.      (Etapa 4)
#   4. Criar papéis e usuários de MENOR PRIVILÉGIO:                  (Etapa 4)
#        filebeat_writer  - só acrescenta documentos nos índices de eventos;
#        siem_correlacao  - lê os eventos e grava só no índice de alertas.
#
# É idempotente: pode ser executado várias vezes sem efeito colateral
# (PUT de template, papel e usuário substitui a definição anterior).
# Todas as senhas chegam por variável de ambiente (nunca por argumento fixo).

set -euo pipefail

ES_URL="${ES_URL:-http://es01:9200}"

# Confere se as variáveis obrigatórias existem antes de qualquer coisa.
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD não definida}"
: "${KIBANA_PASSWORD:?KIBANA_PASSWORD não definida}"
: "${FILEBEAT_PASSWORD:?FILEBEAT_PASSWORD não definida}"
: "${CORRELACAO_PASSWORD:?CORRELACAO_PASSWORD não definida}"

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

# Executa a chamada e falha o setup se o Elasticsearch devolver erro.
# Uso: es_ok DESCRIÇÃO MÉTODO CAMINHO CORPO_JSON
es_ok() {
  local descricao="$1" resposta
  resposta="$(es "$2" "$3" "$4")"
  if grep -q '"error"' <<< "$resposta"; then
    log "ERRO ao ${descricao}: ${resposta}"
    exit 1
  fi
  log "OK: ${descricao}."
}

# --- Index template dos eventos de segurança (Etapa 4) ----------------------
# Tipos explícitos para o que o SIEM consulta: dinheiro em long (centavos
# inteiros), IP como ip (permite busca por faixa) e identificadores como
# keyword (agregação exata). Texto livre só em "message".
# dynamic_templates: qualquer string nova vira keyword, nunca text+keyword.
es_ok "criar o index template bancario-seguranca" PUT "/_index_template/bancario-seguranca" '{
  "index_patterns": ["bancario-seguranca-*"],
  "priority": 200,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "dynamic_templates": [
        { "strings_como_keyword": {
            "match_mapping_type": "string",
            "mapping": { "type": "keyword", "ignore_above": 1024 } } }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "message":    { "type": "text" },
        "service":    { "properties": { "name": { "type": "keyword" } } },
        "user":       { "properties": { "id":   { "type": "keyword" } } },
        "source":     { "properties": { "ip":   { "type": "ip" } } },
        "event": { "properties": {
          "dataset":  { "type": "keyword" },
          "kind":     { "type": "keyword" },
          "category": { "type": "keyword" },
          "action":   { "type": "keyword" },
          "outcome":  { "type": "keyword" },
          "reason":   { "type": "keyword" } } },
        "bancario": { "properties": {
          "transacao_id":       { "type": "keyword" },
          "tipo":               { "type": "keyword" },
          "valor_centavos":     { "type": "long" },
          "destino_pseudonimo": { "type": "keyword" },
          "antifraude_score":   { "type": "integer" } } }
      }
    }
  }
}'

# --- Papéis e usuários de menor privilégio (Etapa 4) ------------------------
# Filebeat: só cria documentos (create_doc), sem ler, apagar ou alterar.
# "monitor" no cluster é exigido pelo Filebeat para checar a versão.
es_ok "criar o papel bancario_ingestao" PUT "/_security/role/bancario_ingestao" '{
  "cluster": ["monitor"],
  "indices": [
    { "names": ["bancario-seguranca-*"],
      "privileges": ["create_doc", "auto_configure"] }
  ]
}'

# Motor de correlação (Etapa 5): lê os eventos e escreve SÓ em siem-alertas.
# "index" permite gravar com id determinístico (reprocessar não duplica).
es_ok "criar o papel siem_correlacao" PUT "/_security/role/siem_correlacao" '{
  "cluster": ["monitor"],
  "indices": [
    { "names": ["bancario-seguranca-*"],
      "privileges": ["read", "view_index_metadata"] },
    { "names": ["siem-alertas"],
      "privileges": ["read", "index", "create_index", "view_index_metadata"] }
  ]
}'

# As senhas são token_urlsafe (A-Z, a-z, 0-9, - e _): seguras dentro do JSON.
es_ok "criar o usuário filebeat_writer" PUT "/_security/user/filebeat_writer" \
  "{\"password\":\"${FILEBEAT_PASSWORD}\",\"roles\":[\"bancario_ingestao\"],\"full_name\":\"Filebeat (ingestão)\"}"

es_ok "criar o usuário siem_correlacao" PUT "/_security/user/siem_correlacao" \
  "{\"password\":\"${CORRELACAO_PASSWORD}\",\"roles\":[\"siem_correlacao\"],\"full_name\":\"Motor de correlação\"}"

log "Setup concluído com sucesso."
