#!/usr/bin/env python3
# Caminho: ferramentas/simulador_eventos.py
"""
Simulador de eventos de segurança da plataforma bancária SINTÉTICA.

Gera tráfego normal e cenários de ataque para alimentar o SIEM e testar as
regras de correlação da Etapa 5. Dois modos, com o mesmo roteiro:

  arquivo  Escreve os eventos direto em logs/simulador.jsonl, no mesmo
           formato do LoggerSeguranca, com horários espalhados nos últimos
           minutos. Rápido e determinístico (--semente); não precisa dos
           serviços no ar.
  http     Faz as requisições de verdade no Gateway, Ledger e Pix
           (portas 8090 a 8092). Os eventos são gravados pelos próprios
           serviços. Para variar o IP de origem, suba os serviços com
           CONFIAR_PROXY=1 (o simulador manda X-Forwarded-For).

Cenários (o número entre parênteses é a regra da Etapa 5 que deve disparar):
  normal            logins e operações pequenas de vários clientes
  ataque_conta      6 falhas de login, login com sucesso e TED de R$ 15.000 (R001)
  forca_bruta_ip    25 falhas de login de um mesmo IP em vários usuários (R002)
  fracionamento_pix 8 Pix de R$ 1.990 do mesmo cliente em poucos minutos (R003)
  conta_laranja     6 clientes diferentes mandando Pix para a mesma chave (R004)
  todos             todos os acima

Uso:
  python ferramentas/simulador_eventos.py --modo arquivo --cenario todos
  python ferramentas/simulador_eventos.py --modo http --cenario ataque_conta

Segredos: a senha dos usuários sintéticos e a chave de pseudônimo vêm de
servicos/.env (gerado por scripts/gerar_env.py) e nunca são exibidas.
Todos os IPs são de faixas reservadas para documentação (RFC 5737).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "servicos"))
from comum.log_seguranca import DATASET, VERSAO_ECS, pseudonimizar  # noqa: E402

PORTAS = {"gateway": 8090, "ledger": 8091, "pix": 8092}
USUARIOS = [f"cliente{n:02d}" for n in range(1, 21)]
IPS_CLIENTES = [f"198.51.100.{n}" for n in range(10, 60)]  # RFC 5737
IP_ATACANTE_CONTA = "203.0.113.66"
IP_FORCA_BRUTA = "203.0.113.99"
CENARIOS = ["normal", "ataque_conta", "forca_bruta_ip", "fracionamento_pix", "conta_laranja"]


@dataclass
class Acao:
    """Um passo do roteiro, independente do modo de execução."""
    tipo: str  # login | transferencia | pix
    usuario: str
    ip: str
    senha_correta: bool = True
    valor_centavos: int = 0
    destino: str = ""
    cenario: str = ""
    extras: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Roteiros dos cenários
# ---------------------------------------------------------------------------

def _conta(rng: random.Random) -> str:
    return f"0001-{rng.randint(100000, 999999)}"


def _chave(rng: random.Random) -> str:
    return f"chave-sintetica-{rng.randint(1, 9999)}@exemplo.test"


def cenario_normal(rng: random.Random, quantidade: int = 40) -> list[Acao]:
    acoes = []
    for _ in range(quantidade):
        usuario, ip = rng.choice(USUARIOS), rng.choice(IPS_CLIENTES)
        if rng.random() < 0.1:  # erro de digitação ocasional
            acoes.append(Acao("login", usuario, ip, senha_correta=False))
        acoes.append(Acao("login", usuario, ip))
        if rng.random() < 0.5:
            acoes.append(Acao("pix", usuario, ip, valor_centavos=rng.randint(500, 80_000), destino=_chave(rng)))
        else:
            acoes.append(Acao("transferencia", usuario, ip, valor_centavos=rng.randint(1_000, 300_000), destino=_conta(rng)))
    return acoes


def cenario_ataque_conta(rng: random.Random) -> list[Acao]:
    """Tomada de conta: senha descoberta por tentativa e dinheiro saindo logo depois."""
    vitima = "cliente07"
    acoes = [Acao("login", vitima, IP_ATACANTE_CONTA, senha_correta=False) for _ in range(6)]
    acoes.append(Acao("login", vitima, IP_ATACANTE_CONTA))
    acoes.append(Acao("transferencia", vitima, IP_ATACANTE_CONTA, valor_centavos=1_500_000, destino=_conta(rng)))
    return acoes


def cenario_forca_bruta_ip(rng: random.Random) -> list[Acao]:
    """Credential stuffing: um IP testando muitos usuários, inclusive inexistentes."""
    alvos = USUARIOS + [f"usuario{n:03d}" for n in range(1, 11)]
    return [Acao("login", rng.choice(alvos), IP_FORCA_BRUTA, senha_correta=False) for _ in range(25)]


def cenario_fracionamento_pix(rng: random.Random) -> list[Acao]:
    """Vários Pix logo abaixo de um limite (R$ 2.000), somando R$ 15.920."""
    usuario, ip = "cliente11", rng.choice(IPS_CLIENTES)
    acoes = [Acao("login", usuario, ip)]
    acoes += [Acao("pix", usuario, ip, valor_centavos=199_000, destino=_chave(rng)) for _ in range(8)]
    return acoes


def cenario_conta_laranja(rng: random.Random) -> list[Acao]:
    """Clientes diferentes mandando Pix para a mesma chave de destino."""
    chave_laranja = "chave-laranja-0001@exemplo.test"
    acoes = []
    for usuario in rng.sample(USUARIOS, 6):
        ip = rng.choice(IPS_CLIENTES)
        acoes.append(Acao("login", usuario, ip))
        acoes.append(Acao("pix", usuario, ip, valor_centavos=rng.randint(90_000, 150_000), destino=chave_laranja))
    return acoes


ROTEIROS = {
    "normal": cenario_normal,
    "ataque_conta": cenario_ataque_conta,
    "forca_bruta_ip": cenario_forca_bruta_ip,
    "fracionamento_pix": cenario_fracionamento_pix,
    "conta_laranja": cenario_conta_laranja,
}


def montar_roteiro(cenarios: list[str], rng: random.Random) -> list[Acao]:
    roteiro = []
    for nome in cenarios:
        for acao in ROTEIROS[nome](rng):
            acao.cenario = nome
            roteiro.append(acao)
    return roteiro


# ---------------------------------------------------------------------------
# Modo arquivo
# ---------------------------------------------------------------------------

def _iso(instante: datetime) -> str:
    return instante.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def evento_simulado(acao: Acao, instante: datetime, chave: bytes, rng: random.Random) -> dict:
    """Monta o mesmo documento que o LoggerSeguranca do serviço gravaria."""
    if acao.tipo == "login":
        existe = acao.usuario in USUARIOS
        sucesso = existe and acao.senha_correta
        servico, categoria = "gateway", "authentication"
        resultado = "success" if sucesso else "failure"
        mensagem = "Login bem-sucedido" if sucesso else "Falha de login"
        motivo = None if sucesso else ("senha_invalida" if existe else "usuario_inexistente")
        bancario = None
    else:
        servico = "ledger" if acao.tipo == "transferencia" else "pix"
        categoria, resultado, motivo = "transacao", "success", None
        mensagem = "Transferência efetivada" if acao.tipo == "transferencia" else "Pix enviado"
        bancario = {
            "transacao_id": f"sim-{rng.getrandbits(64):016x}",
            "tipo": "transferencia" if acao.tipo == "transferencia" else "pix",
            "valor_centavos": acao.valor_centavos,
            "destino_pseudonimo": pseudonimizar(acao.destino, chave),
            "antifraude_score": rng.randint(5, 45),
        }

    registro = {
        "@timestamp": _iso(instante),
        "ecs": {"version": VERSAO_ECS},
        "service": {"name": servico},
        "event": {"dataset": DATASET, "kind": "event", "category": [categoria],
                  "action": "login" if acao.tipo == "login" else ("transferencia" if acao.tipo == "transferencia" else "pix_envio"),
                  "outcome": resultado},
        "message": mensagem,
        "user": {"id": acao.usuario},
        "source": {"ip": acao.ip},
        # Marca o que veio do simulador, para filtrar no Kibana se preciso.
        "tags": ["simulador", f"cenario:{acao.cenario}"],
    }
    if motivo:
        registro["event"]["reason"] = motivo
    if bancario:
        registro["bancario"] = bancario
    return registro


def executar_arquivo(roteiro: list[Acao], chave: bytes, rng: random.Random, minutos: int) -> Path:
    """Espalha o roteiro nos últimos `minutos`, mantendo a ordem dos passos.

    Cada cenário de ataque fica contido em poucos minutos, como na vida
    real, e por isso cabe nas janelas das regras (5 a 30 min)."""
    destino = RAIZ / "logs" / "simulador.jsonl"
    destino.parent.mkdir(exist_ok=True)
    fim = datetime.now(timezone.utc)
    passo = timedelta(seconds=max(1, minutos * 60 // max(1, len(roteiro))))
    instante = fim - passo * len(roteiro)
    with destino.open("a", encoding="utf-8") as saida:
        for acao in roteiro:
            instante += passo
            saida.write(json.dumps(evento_simulado(acao, instante, chave, rng), ensure_ascii=False, separators=(",", ":")) + "\n")
    return destino


# ---------------------------------------------------------------------------
# Modo http
# ---------------------------------------------------------------------------

def _post(servico: str, caminho: str, corpo: dict, ip: str, token: str | None = None) -> tuple[int, dict]:
    cabecalhos = {"Content-Type": "application/json", "X-Forwarded-For": ip}
    if token:
        cabecalhos["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{PORTAS[servico]}{caminho}",
                                 data=json.dumps(corpo).encode(), method="POST", headers=cabecalhos)
    try:
        with urllib.request.urlopen(req, timeout=10) as resposta:  # só 127.0.0.1
            return resposta.status, json.loads(resposta.read() or b"{}")
    except urllib.error.HTTPError as erro:
        return erro.code, {}


def executar_http(roteiro: list[Acao], senha: str) -> dict:
    tokens: dict[str, str] = {}
    contagem: dict[str, int] = {}
    for acao in roteiro:
        if acao.tipo == "login":
            tentativa = senha if acao.senha_correta else "senha-errada-" + acao.ip
            status, corpo = _post("gateway", "/login", {"usuario": acao.usuario, "senha": tentativa}, acao.ip)
            if status == 200:
                tokens[acao.usuario] = corpo["token"]
        elif acao.usuario not in tokens:
            status = 0  # sem login válido antes: passo ignorado
        elif acao.tipo == "transferencia":
            status, _ = _post("ledger", "/transferencias", {"conta_destino": acao.destino, "valor_centavos": acao.valor_centavos}, acao.ip, tokens[acao.usuario])
        else:
            status, _ = _post("pix", "/pix", {"chave_destino": acao.destino, "valor_centavos": acao.valor_centavos}, acao.ip, tokens[acao.usuario])
        rotulo = f"{acao.tipo} HTTP {status}"
        contagem[rotulo] = contagem.get(rotulo, 0) + 1
    return contagem


# ---------------------------------------------------------------------------

def ler_env_servicos() -> dict:
    arquivo = RAIZ / "servicos" / ".env"
    if not arquivo.exists():
        sys.exit("servicos/.env não encontrado: rode python scripts/gerar_env.py")
    valores = {}
    for linha in arquivo.read_text(encoding="utf-8").splitlines():
        if "=" in linha and not linha.lstrip().startswith("#"):
            chave, valor = linha.split("=", 1)
            valores[chave.strip()] = valor.strip()
    return valores


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulador de eventos de segurança (dados sintéticos).")
    parser.add_argument("--modo", choices=["arquivo", "http"], default="arquivo")
    parser.add_argument("--cenario", choices=CENARIOS + ["todos"], default="todos")
    parser.add_argument("--minutos", type=int, default=20, help="modo arquivo: janela de tempo dos eventos")
    parser.add_argument("--semente", type=int, help="semente aleatória (roteiro reprodutível)")
    args = parser.parse_args(argv)

    rng = random.Random(args.semente)
    cenarios = CENARIOS if args.cenario == "todos" else [args.cenario]
    roteiro = montar_roteiro(cenarios, rng)
    env = ler_env_servicos()

    if args.modo == "arquivo":
        destino = executar_arquivo(roteiro, env["LOG_PSEUDONIMO_CHAVE"].encode(), rng, args.minutos)
        print(f"[OK] {len(roteiro)} eventos ({', '.join(cenarios)}) gravados em {destino.relative_to(RAIZ)}")
    else:
        if env.get("CONFIAR_PROXY", "0") != "1":
            print("[AVISO] CONFIAR_PROXY != 1 nos serviços: todos os eventos terão o IP do Docker, não o simulado.")
        contagem = executar_http(roteiro, env["SENHA_USUARIOS_SINTETICOS"])
        print(f"[OK] {len(roteiro)} passos executados ({', '.join(cenarios)}):")
        for rotulo, total in sorted(contagem.items()):
            print(f"     {rotulo}: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
