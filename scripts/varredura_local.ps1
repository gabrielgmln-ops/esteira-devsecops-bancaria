# Caminho: scripts/varredura_local.ps1
#
# Equivalente para Windows de scripts/varredura_local.sh: roda na máquina os
# mesmos scanners da esteira, com as mesmas imagens Docker de versão fixada,
# e grava os relatórios JSON em relatorios\ (ignorada pelo git).
#
# Uso (na raiz do repositório, com o Docker Desktop aberto):
#   powershell -ExecutionPolicy Bypass -File scripts\varredura_local.ps1
#
# Como na esteira, o script NÃO falha por causa de achados: ele apenas
# relata. Quem decide se o merge é barrado é o gate (Etapa 3).

$ErrorActionPreference = 'Stop'

# Mesmas versões do workflow. Ao atualizar, mude nos três lugares.
$SemgrepImage  = 'semgrep/semgrep:1.181.1'
$TrivyImage    = 'aquasec/trivy:0.76.0'
$GitleaksImage = 'zricethezav/gitleaks:v8.30.1'
$TrivyDb       = 'mirror.gcr.io/aquasec/trivy-db'
$Servicos      = 'gateway', 'ledger', 'pix', 'antifraude'

$Raiz = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Raiz
New-Item -ItemType Directory -Force relatorios | Out-Null
# Cache do banco do Trivy fora do repositório, reaproveitado entre execuções.
$CacheTrivy = Join-Path $env:USERPROFILE '.cache\trivy-esteira'
New-Item -ItemType Directory -Force $CacheTrivy | Out-Null

# Executa um comando nativo e interrompe o script se ele falhar.
# ($ErrorActionPreference não vale para executáveis externos no PowerShell 5.1.)
function Invoke-Nativo {
    param([string]$Etapa, [scriptblock]$Comando)
    & $Comando
    if ($LASTEXITCODE -ne 0) { throw "Falha em '$Etapa' (código $LASTEXITCODE)." }
}

function Invoke-Trivy {
    param([string[]]$Argumentos)
    docker run --rm -v "${Raiz}:/src" -w /src `
        -v "${CacheTrivy}:/root/.cache/trivy" `
        -e "TRIVY_DB_REPOSITORY=$TrivyDb" `
        $TrivyImage @Argumentos
}

Write-Host '==> [1/4] SAST (Semgrep)'
Invoke-Nativo 'Semgrep' {
    docker run --rm -v "${Raiz}:/src" -w /src $SemgrepImage `
        semgrep scan --metrics=off --quiet `
        --config p/python --config p/flask `
        --config p/dockerfile --config p/github-actions `
        --config .semgrep/regras-bancarias.yml `
        --json-output=relatorios/semgrep.json
}

Write-Host '==> [2/4] SCA (Trivy fs em servicos/requirements.txt)'
Invoke-Nativo 'Trivy fs' {
    Invoke-Trivy @('fs', '--quiet', '--scanners', 'vuln', '--exit-code', '0',
        '--format', 'json', '--output', 'relatorios/trivy-sca.json',
        'servicos/requirements.txt')
}

Write-Host '==> [3/4] Imagens (build + Trivy image --ignore-unfixed)'
foreach ($servico in $Servicos) {
    Write-Host "    - $servico"
    $tar = "relatorios/$servico.tar"
    Invoke-Nativo "build $servico" {
        docker build --quiet --build-arg "SERVICO=$servico" `
            -t "bancario/${servico}:varredura" servicos | Out-Null
    }
    Invoke-Nativo "save $servico" { docker save "bancario/${servico}:varredura" -o $tar }
    Invoke-Nativo "Trivy image $servico" {
        Invoke-Trivy @('image', '--quiet', '--scanners', 'vuln', '--ignore-unfixed',
            '--exit-code', '0', '--input', $tar,
            '--format', 'json', '--output', "relatorios/trivy-imagem-$servico.json")
    }
    Remove-Item $tar -Force
}

Write-Host '==> [4/4] Segredos (Gitleaks em todo o histórico)'
Invoke-Nativo 'Gitleaks' {
    docker run --rm -v "${Raiz}:/repo" $GitleaksImage `
        git /repo --redact --no-banner --exit-code 0 `
        --report-format json --report-path /repo/relatorios/gitleaks.json
}

# Conta achados por severidade. Atenção: @($null).Count vale 1 no
# PowerShell; por isso os nulos são filtrados antes de contar.
function Get-Resumo {
    param($Severidades)
    $lista = @($Severidades | Where-Object { $_ })
    if ($lista.Count -eq 0) { return 'sem achados' }
    ($lista | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
}

Write-Host "`n================ RESUMO ================"
$semgrep = Get-Content relatorios\semgrep.json -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host ("Semgrep  : " + (Get-Resumo ($semgrep.results | ForEach-Object { $_.extra.severity })))

foreach ($arquivo in Get-ChildItem relatorios\trivy-*.json | Sort-Object Name) {
    $dados = Get-Content $arquivo.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $sev = $dados.Results | ForEach-Object { $_.Vulnerabilities } | ForEach-Object { $_.Severity }
    Write-Host ("{0,-26}: {1}" -f $arquivo.BaseName, (Get-Resumo $sev))
}

# No PowerShell 5.1 o ConvertFrom-Json devolve a lista JSON inteira como UM
# objeto; o ForEach-Object a desenrola em itens antes de contar.
$gitleaks = @(Get-Content relatorios\gitleaks.json -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ })
Write-Host "Gitleaks : $($gitleaks.Count) achado(s)"
foreach ($a in $gitleaks) {
    Write-Host ("   - {0} em {1}:{2} ({3})" -f $a.RuleID, $a.File, $a.StartLine, $a.Commit.Substring(0, 7))
}
Write-Host 'Relatórios completos em relatorios\'
