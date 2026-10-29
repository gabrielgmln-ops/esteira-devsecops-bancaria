#!/usr/bin/env bash
# Caminho: scripts/varredura_local.sh
#
# Roda na máquina os mesmos scanners da esteira (.github/workflows/devsecops.yml),
# com as mesmas imagens Docker de versão fixada, e grava os relatórios JSON
# em relatorios/ (ignorada pelo git).
#
# Uso (na raiz do repositório):
#   bash scripts/varredura_local.sh
#
# Requisitos: Docker e python3 (só para o resumo final).
# Como na esteira, o script NÃO falha por causa de achados: ele apenas
# relata. Quem decide se o merge é barrado é o gate (Etapa 3).

set -euo pipefail

# Mesmas versões do workflow. Ao atualizar, mude nos dois lugares.
SEMGREP_IMAGE="semgrep/semgrep:1.181.1"
TRIVY_IMAGE="aquasec/trivy:0.76.0"
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1"
TRIVY_DB="mirror.gcr.io/aquasec/trivy-db"
SERVICOS=(gateway ledger pix antifraude)

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"
mkdir -p relatorios
# Cache do banco do Trivy fora do repositório, reaproveitado entre execuções.
CACHE_TRIVY="${HOME}/.cache/trivy-esteira"
mkdir -p "$CACHE_TRIVY"

trivy() {
  docker run --rm -v "$RAIZ:/src" -w /src \
    -v "$CACHE_TRIVY:/root/.cache/trivy" \
    -e TRIVY_DB_REPOSITORY="$TRIVY_DB" \
    "$TRIVY_IMAGE" "$@"
}

echo "==> [1/4] SAST (Semgrep)"
docker run --rm -v "$RAIZ:/src" -w /src "$SEMGREP_IMAGE" \
  semgrep scan --metrics=off --quiet \
    --config p/python --config p/flask \
    --config p/dockerfile --config p/github-actions \
    --config .semgrep/regras-bancarias.yml \
    --json-output=relatorios/semgrep.json

echo "==> [2/4] SCA (Trivy fs em servicos/requirements.txt)"
trivy fs --quiet --scanners vuln --exit-code 0 \
  --format json --output relatorios/trivy-sca.json servicos/requirements.txt

echo "==> [3/4] Imagens (build + Trivy image --ignore-unfixed)"
for servico in "${SERVICOS[@]}"; do
  echo "    - $servico"
  docker build --quiet --build-arg SERVICO="$servico" \
    -t "bancario/$servico:varredura" servicos > /dev/null
  docker save "bancario/$servico:varredura" -o "relatorios/$servico.tar"
  trivy image --quiet --scanners vuln --ignore-unfixed --exit-code 0 \
    --input "relatorios/$servico.tar" \
    --format json --output "relatorios/trivy-imagem-$servico.json"
  rm -f "relatorios/$servico.tar"
done

echo "==> [4/4] Segredos (Gitleaks em todo o histórico)"
docker run --rm --user "$(id -u):$(id -g)" -v "$RAIZ:/repo" "$GITLEAKS_IMAGE" \
  git /repo --redact --no-banner --exit-code 0 \
    --report-format json --report-path /repo/relatorios/gitleaks.json

# Resumo por severidade, lido dos próprios relatórios.
python3 - <<'PY'
import json
from collections import Counter
from pathlib import Path

rel = Path("relatorios")
print("\n================ RESUMO ================")

semgrep = json.loads((rel / "semgrep.json").read_text(encoding="utf-8"))
cont = Counter(r["extra"]["severity"] for r in semgrep.get("results", []))
print(f"Semgrep  : {dict(cont) or 'sem achados'}")

for arquivo in sorted(rel.glob("trivy-*.json")):
    dados = json.loads(arquivo.read_text(encoding="utf-8"))
    vulns = [v for r in dados.get("Results") or [] for v in r.get("Vulnerabilities") or []]
    cont = Counter(v["Severity"] for v in vulns)
    print(f"{arquivo.stem:<26}: {dict(cont) or 'sem achados'}")

gitleaks = json.loads((rel / "gitleaks.json").read_text(encoding="utf-8"))
print(f"Gitleaks : {len(gitleaks)} achado(s)")
for achado in gitleaks:
    print(f"   - {achado['RuleID']} em {achado['File']}:{achado['StartLine']} ({achado['Commit'][:7]})")
print("Relatórios completos em relatorios/")
PY
