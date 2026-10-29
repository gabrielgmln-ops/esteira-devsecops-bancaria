#!/usr/bin/env bash
# Caminho: ci/proteger_branch.sh
#
# Protege a branch main: nenhum código entra sem passar pelo gate.
#   - exige os checks "Gate de severidade" e "Testes unitários" verdes;
#   - exige a branch atualizada com a main antes do merge (strict);
#   - exige pull request (sem push direto), com a conversa resolvida;
#   - proíbe force push e exclusão da main;
#   - vale também para administradores (enforce_admins).
#
# Uso (com o GitHub CLI autenticado como administrador do repositório):
#   bash ci/proteger_branch.sh [dono/repositorio]
#
# Idempotente: o PUT substitui a proteção inteira; rodar de novo não duplica.
# Repositório público ou plano pago: a API recusa a proteção em privado free.

set -euo pipefail

REPO="${1:-gabrielgmln-ops/esteira-devsecops-bancaria}"
BRANCH="main"

command -v gh > /dev/null || { echo "Instale o GitHub CLI (gh)." >&2; exit 1; }
gh auth status > /dev/null 2>&1 || { echo "Rode 'gh auth login' antes." >&2; exit 1; }

echo "==> Protegendo $REPO:$BRANCH"
# required_approving_review_count = 0: projeto de uma pessoa só; o PR é
# exigido para o gate rodar, não para ter revisor. Com equipe, suba para 1.
gh api --method PUT "repos/$REPO/branches/$BRANCH/protection" \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Gate de severidade", "Testes unitários"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": true
  },
  "required_conversation_resolution": true,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

echo "==> Proteção aplicada. Checks exigidos:"
gh api "repos/$REPO/branches/$BRANCH/protection/required_status_checks" \
  --jq '.contexts[]'
