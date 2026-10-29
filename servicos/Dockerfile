# Caminho: servicos/Dockerfile
#
# Imagem única parametrizada para os quatro serviços.
# Build (a partir da pasta servicos/):
#   docker build --build-arg SERVICO=gateway -t bancario/gateway:local .
#
# Boas práticas aplicadas:
#   - Imagem base slim fixada por DIGEST (imutável). Para atualizar:
#       docker pull python:3.13-slim
#       docker inspect python:3.13-slim --format '{{index .RepoDigests 0}}'
#   - Usuário sem privilégios (uid 10001); sistema de arquivos só leitura
#     no compose; nada de shell como root em execução.
#   - Dependências instaladas sem cache e com versões fixadas.

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

# Shell com "pipefail": falhas no meio de um pipe interrompem o build.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Serviço a empacotar: gateway | ledger | pix | antifraude
ARG SERVICO
RUN test -n "$SERVICO" || (echo "Informe --build-arg SERVICO=<nome>" && exit 1)

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOG_DIR=/var/log/bancario \
    SERVICO=${SERVICO}

# Atualiza pacotes do sistema e cria o usuário de execução.
# O "apt-get upgrade" é uma escolha consciente: aplica correções de CVEs
# publicadas depois da imagem base (o Semgrep o reporta como MÉDIA).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/log/bancario \
    && chown app:app /var/log/bancario

WORKDIR /app

COPY requirements.txt .
# Instala as dependências e em seguida REMOVE o pip: ele não é usado em
# execução e traz cópias próprias de urllib3, msgpack e setuptools
# (pip/_vendor), que o Trivy reportava como CVEs HIGH (Etapa 2).
# Sem pip, um invasor dentro do contêiner também não instala pacotes.
RUN pip install -r requirements.txt \
    && pip uninstall -y pip

# Somente o código necessário: módulo comum + o serviço escolhido.
COPY comum/ ./comum/
COPY ${SERVICO}/ ./${SERVICO}/

USER app

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/saude', timeout=2).status == 200 else 1)"]

# gunicorn em vez do servidor de desenvolvimento do Flask.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:8000 --workers 2 --threads 4 --access-logfile - \"${SERVICO}.app:app\""]
