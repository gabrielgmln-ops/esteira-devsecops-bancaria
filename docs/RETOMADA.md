# Retomada: Esteira DevSecOps + SIEM caseiro

Nota de passagem da sessão na nuvem (Claude Code, 28/10/2026) para a sessão no
PC Windows. Leia esta nota antes de qualquer coisa.

## Estado atual

- Etapas **0 a 5 prontas**. Falta só a Etapa 6 (painel e README).
- Etapa 5 validada no PC: o motor leu 147 eventos e gerou 5 alertas (os 4
  cenários do simulador e mais o ataque real via HTTP). A segunda passada
  reconheceu os 5 pelo id, sem duplicar. 50 testes no total (20 das regras).
- Comportamento a saber: a R001 conta as falhas **por usuário, qualquer
  IP**. No laboratório, uma falha da força bruta (IP `.99`) entrou na
  janela da tomada de conta (IP `.66`), e o alerta mostra isso nas
  evidências. Também: quando a regra dispara, a janela é esvaziada (rearme),
  então o alerta da R004 lista os 5 primeiros pagadores, não os 6.
- Etapa 4 validada no PC: o Filebeat ingeriu 147 eventos (138 do simulador
  e 9 gravados pelos serviços reais), `verificar_ingestao.py` com 5 `[OK]`,
  inclusive as duas provas de menor privilégio (403).
- **Para a Etapa 5:** no cenário `ataque_conta` via HTTP, o Antifraude
  APROVOU a TED de R$ 15.000 logo depois de 6 falhas de login. É justamente
  o que a regra R001 precisa pegar, porque o antifraude por transação não
  vê o histórico de login.
- Etapa 3: job `gate` (`ci/gate_severidade.py`) com exceções em
  `ci/excecoes.yml`; 16 testes do gate (30 no total). Gate APROVADO no
  estado atual: 0 CVE nas imagens e os 4 falsos positivos do Gitleaks
  aceitos por exceção, válidas até 2027-04-30.
- **Proteção da `main` ainda não aplicada:** rodar `bash ci/proteger_branch.sh`
  com o `gh` autenticado. Depois disso, todo commit entra por pull request.
- Repositório: `gabrielgmln-ops/esteira-devsecops-bancaria`; a primeira
  execução do Actions (`d18d12b`) passou.
- Validado no PC Windows em 29/10/2026:
  - SIEM com as 4 checagens `[OK]`;
  - `14 passed` no pytest;
  - build das 4 imagens e `GET /saude` = 200 nas portas 8090 a 8093;
  - pacotes públicos do Semgrep baixados (178 regras rodaram: 9 próprias
    e 169 dos pacotes).
- 9 regras Semgrep customizadas, todas aprovadas no `semgrep --test`.
- Semgrep no PC: 0 achados. Os 5 de severidade média e 1 de baixa vistos na
  nuvem vinham das regras tiradas do repositório `semgrep-rules`, que tem
  mais regras do que os pacotes publicados no registro.
- `actionlint` e `shellcheck` sem erros.

### Achados da Etapa 2 (resolvidos na Etapa 3)

- **Trivy imagem:** 5 HIGH com correção em cada uma das 4 imagens
  (`urllib3` 2.7.0, `msgpack` 1.1.2 e `setuptools` 70.3.0). Não vinham do
  `requirements.txt`: eram cópias embutidas no próprio pip
  (`pip/_vendor/`). **Corrigido:** o Dockerfile desinstala o pip depois de
  instalar as dependências, porque ele não é usado em execução. Resultado:
  0 CVE, com `/saude` respondendo nas 4 portas.
- **Gitleaks:** 4 achados, todos falsos positivos do commit `9a839ca`:
  - 3 `generic-api-key` em `siem/.env.example` (linhas 21 a 23): eram
    marcadores do tipo `defina-pelo-gerar_env-com-32-ou-mais-caracteres`;
  - 1 `curl-auth-user` em `siem/docker-compose.yml:58`: é
    `elastic:$${ELASTIC_PASSWORD}`, uma referência a variável, não uma
    senha.

  Como ficam no histórico, entraram como exceções em `ci/excecoes.yml`
  (pelo fingerprint, com justificativa e validade até 2027-04-30).

## Commits

| Hash | Etapa | Mensagem |
|---|---|---|
| `9a839ca` | 0 | feat(siem): adiciona stack ELK local com autenticação para o SIEM |
| `21e0456` | 1 | ci(sast): adiciona esteira com Semgrep, regras bancárias e serviços sintéticos |
| `7c583c0` | 1 | fix: ajusta portabilidade para Windows e conflito de portas |
| `d18d12b` | - | docs: nota de retomada da sessão |
| `663e3ad` | - | fix(scripts): corrige gerar_env.py no Windows (os.getuid inexistente) |
| `5d43d63` | 2 | ci(sca): adiciona Trivy em dependências e imagens e Gitleaks em segredos |
| `8cd3c95` | 3 | ci(gate): adiciona gate de severidade, exceções e proteção da main |
| `f5cd0e5` | 4 | feat(siem): adiciona ingestão dos logs com Filebeat e simulador de eventos |
| (Etapa 5) | 5 | feat(siem): adiciona motor de correlação com 4 regras e índice de alertas |

## Etapas

| # | Etapa | Situação |
|---|---|---|
| 0 | Setup do SIEM local (ELK) | Pronta (`9a839ca`) |
| 1 | Pipeline com SAST (Semgrep) | Pronta (`21e0456`, `7c583c0`) |
| 2 | Varredura de dependências e imagens (Trivy) e de segredos (Gitleaks) | Pronta (ver commits) |
| 3 | Gate que barra severidade alta + proteção da branch main | Pronta (proteção a aplicar) |
| 4 | Ingestão dos logs no SIEM (Filebeat) | Pronta |
| 5 | Regras de correlação e alertas | Pronta |
| 6 | Painel no Kibana e documentação (README) | Pendente |

## Estrutura

```
.github/workflows/devsecops.yml   testes + SAST (Etapa 1) + sca, imagens e segredos (Etapa 2)
.semgrep/regras-bancarias.yml     9 regras do domínio bancário
.semgrep/regras-bancarias.py      casos de teste das regras
.semgrepignore                    exclusões da varredura
scripts/gerar_env.py              gera siem/.env e servicos/.env com segredos aleatórios
scripts/varredura_local.sh/.ps1   roda Semgrep, Trivy e Gitleaks na máquina (relatorios/)
ci/gate_severidade.py             decide se o merge passa (python ci/gate_severidade.py)
ci/excecoes.yml                   único lugar de exceções, com justificativa e validade
ci/proteger_branch.sh             exige o gate na main (gh api)
ci/testes/                        testes do gate
siem/docker-compose.yml           es01 + setup + kibana + filebeat
siem/setup/setup.sh               senha do kibana_system, index template, papéis e usuários (idempotente)
siem/filebeat/filebeat.yml        ../logs/*.jsonl -> bancario-seguranca-AAAA.MM.DD
siem/scripts/verificar_siem.py    verificação de saúde do SIEM
siem/scripts/verificar_ingestao.py eventos ingeridos, tipos e provas de menor privilégio
ferramentas/simulador_eventos.py  tráfego normal e 4 cenários de ataque (modos arquivo e http)
siem/correlacao/regras.py         regras R001 a R004 como funções puras
siem/correlacao/regras.yml        parâmetros das regras (limites, janelas, severidade)
siem/correlacao/motor.py          busca eventos, aplica as regras e grava em siem-alertas
siem/correlacao/testes/           testes das regras (sem Elasticsearch)
servicos/                         Gateway, Ledger, Pix, Antifraude (Flask) + Dockerfile + testes
logs/                             destino dos logs JSONL dos serviços (ignorado no git)
```

## Decisões tomadas

1. **SIEM: ELK em vez de Wazuh.** Dá correlação sob medida em Python e painel
   no Kibana com licença básica. Usa as imagens oficiais do Docker Hub
   (`elasticsearch:8.17.4`, `kibana:8.17.4`).
2. **Segurança do laboratório:** autenticação ligada, TLS HTTP desligado,
   portas presas em `127.0.0.1`. O Kibana usa o usuário `kibana_system` e
   nunca o `elastic`.
3. **Sem `bootstrap.memory_lock`:** falha em Docker rootless e no WSL.
4. **Marcas d'água de disco em valor absoluto** (2gb/1gb/512mb): com os
   percentuais padrão, um disco grande e cheio deixa o cluster "red".
5. **Segredos:** só em `siem/.env` e `servicos/.env` (permissão 600, fora do
   git), gerados por `scripts/gerar_env.py`. Nenhum segredo tem valor padrão
   no código: se faltar, o serviço não sobe.
6. **Serviços sintéticos em Flask** para ter código real para o SAST e
   eventos reais para o SIEM:
   - dinheiro sempre em centavos inteiros;
   - se o Antifraude não responder, a operação é negada;
   - chave Pix e conta de destino aparecem no log só como pseudônimo HMAC;
   - campos de senha ou token são recusados no logger;
   - cada serviço recebe só os segredos de que precisa.
7. **Formato de log:** JSON por linha, com campos no padrão ECS
   (`event.action`, `event.outcome`, `user.id`, `source.ip`, `bancario.*`).
   O dataset é `bancario.seguranca`. Ações: `login`, `transferencia`,
   `pix_envio` e `avaliacao_antifraude`.
8. **Severidades para o gate (Etapa 3):**
   - Semgrep: ERROR = alta e barra o merge; WARNING = média; INFO = baixa.
   - Trivy: HIGH e CRITICAL barram.
   - Gitleaks: qualquer achado barra.
9. **Scanners por imagem Docker de versão fixada**, em vez de actions de
   terceiros: `semgrep/semgrep:1.181.1`, `aquasec/trivy:0.76.0` e
   `zricethezav/gitleaks:v8.30.1`. As actions oficiais estão fixadas por SHA
   de commit.
10. **Imagem base dos serviços:** `python:3.13-slim` fixada por digest.
    Roda com usuário sem privilégios, sistema de arquivos somente leitura e
    `cap_drop: ALL`.
11. **Portas no PC:**
    - serviços: 8090 a 8093 (8080 = AgentService, 8081 = Ledger API,
      8082 = Pix Simulado);
    - Elasticsearch: 9200;
    - Kibana: 5601.

## Plano das etapas pendentes (já desenhado)

- **Etapa 2:** jobs `sca` (Trivy em modo fs sobre `servicos/requirements.txt`),
  `imagens` (build das 4 imagens + Trivy image com `--ignore-unfixed`) e
  `segredos` (Gitleaks com `fetch-depth: 0` e `--redact`). Cada job publica
  seu relatório JSON como artefato.
- **Etapa 3:** job `gate` com `needs:` em todos os scanners. Ele baixa os
  artefatos e roda `ci/gate_severidade.py`, que:
  - normaliza os achados;
  - aplica `ci/excecoes.yml` (exceções com justificativa e data de validade);
  - escreve um resumo em `$GITHUB_STEP_SUMMARY`;
  - sai com código 1 se houver achado de severidade alta.

  Também inclui `ci/proteger_branch.sh` (via `gh api`) para exigir os checks
  na `main`, e `scripts/varredura_local.sh` para rodar os mesmos scanners na
  máquina.
- **Etapa 4:** Filebeat (`elastic/filebeat:8.17.4`) lê `../logs/*.jsonl` e
  grava em `bancario-seguranca-AAAA.MM.DD`. O `setup.sh` passa a criar o
  index template e os usuários de menor privilégio `filebeat_writer` e
  `siem_correlacao` (FILEBEAT_PASSWORD e CORRELACAO_PASSWORD no `.env.example`
  com o marcador `defina-pelo-gerar_env`). Entra também o
  `ferramentas/simulador_eventos.py`, que gera tráfego normal e cenários de
  ataque, com modos `arquivo` e `http`.
- **Etapa 5:** motor de correlação em Python, com regras puras e testáveis
  sem Elasticsearch e parâmetros em `siem/correlacao/regras.yml`. Grava os
  alertas no índice `siem-alertas` com id determinístico (sem duplicar).
  Regras:
  - R001: 5 ou mais falhas de login do mesmo usuário em 10 min, seguidas de
    login com sucesso e transferência ou Pix de R$ 10.000 ou mais em até
    30 min (crítica);
  - R002: força bruta / credential stuffing por IP, com 20 ou mais falhas em
    5 min;
  - R003: fracionamento de Pix (muitos Pix do mesmo usuário em 10 min
    somando um valor alto);
  - R004: muitos Pix para o mesmo destino (pseudônimo) vindos de usuários
    diferentes, indício de conta laranja.
- **Etapa 6:** `siem/kibana/provisionar_painel.py`, que cria via API os data
  views e o dashboard "SIEM Bancário" (alertas por regra e severidade, linha
  do tempo, top usuários e IPs, falhas de login). Inclui o README completo
  com arquitetura, como rodar, decisões e limitações.

## Pendências e riscos conhecidos

1. ~~Build das imagens não validado~~: validado no PC em 29/10/2026.
2. ~~Pacotes públicos do Semgrep~~: confirmados no PC (169 regras dos
   pacotes). Falta só ler o log do job SAST no Actions, que exige login.
3. **Jobs da Etapa 2 ainda não rodaram no GitHub:** conferir após o push.
   O `varredura_local.sh` foi validado com shellcheck; quem o executou de
   ponta a ponta foi o `.ps1` equivalente.
4. **Windows / Docker Desktop:** se o Elasticsearch não subir por
   `vm.max_map_count`, rodar
   `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`.
5. **`CONFIAR_PROXY=1`** existe só para o simulador variar IPs no
   laboratório. Em produção, só com um proxy reverso confiável.
6. **Upload do SARIF para Code Scanning:** só funciona em repositório público
   ou com GitHub Advanced Security. O passo está com `continue-on-error`.

## O que o senhor precisa fornecer

- Criar o repositório **vazio** `gabrielgmln-ops/esteira-devsecops-bancaria`
  no GitHub (sem README, sem .gitignore, sem licença) e dizer se será público
  ou privado. Público libera o Code Scanning de graça.
- Docker Desktop aberto, com ao menos 4 GB de RAM para o WSL.
- Python 3.12 ou mais recente no PC (para `scripts/gerar_env.py`, testes e
  simulador).
- Para a Etapa 3: permissão para ativar a proteção de branch na `main`
  (o `gh` autenticado como administrador do repositório).

## Como retomar

```powershell
cd "C:\SegundoCerebro\03 - Projetos\esteira-devsecops-bancaria"
python scripts\gerar_env.py
cd siem; docker compose up -d --wait; python scripts\verificar_siem.py; cd ..
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r servicos\requirements-dev.txt
python -m pytest servicos\testes -q
```

Resultado esperado: 4 checagens `[OK]` no SIEM e `50 passed` nos testes
(`python -m pytest servicos\testes ci\testes siem\correlacao\testes -q`).

Ingestão (Etapa 4), com o SIEM no ar:

```powershell
python ferramentas\simulador_eventos.py --modo arquivo --cenario todos --semente 42
python siem\scripts\verificar_ingestao.py   # aguarde ~10 s; esperado: 5 [OK]
python siem\correlacao\motor.py             # esperado: alertas R001 a R004
```
