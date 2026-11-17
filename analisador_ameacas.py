import re
import json
from collections import Counter
from datetime import datetime

# ==============================================================================
# PROJETO: AUDITORIA DE LOGS DE SEGURANÇA & TRIAGEM ASSISTIDA POR IA
# Autor: Leonardo de Freitas Pintar
# Descrição: Analisa logs de autenticação (SSH/Firewall), identifica tentativas
#            de ataque de força bruta (Brute Force) e estrutura diagnóstico
#            técnico e executivo pronto para integração com modelos de IA.
# ==============================================================================

LIMITE_TENTATIVAS_SUSPEITAS = 4

# Amostra realista de logs de autenticação de servidor Linux / Firewall de borda
LOGS_AUTENTICACAO = """
2026-11-17 02:14:01 SERVER-FW sshd[4102]: Failed password for invalid user admin from 185.220.101.45 port 51234 ssh2
2026-11-17 02:14:04 SERVER-FW sshd[4105]: Failed password for root from 185.220.101.45 port 51238 ssh2
2026-11-17 02:14:07 SERVER-FW sshd[4109]: Failed password for root from 185.220.101.45 port 51240 ssh2
2026-11-17 02:14:10 SERVER-FW sshd[4112]: Failed password for invalid user ubuntu from 185.220.101.45 port 51245 ssh2
2026-11-17 02:14:12 SERVER-FW sshd[4115]: Failed password for invalid user oracle from 185.220.101.45 port 51250 ssh2
2026-11-17 08:05:22 SERVER-FW sshd[4210]: Accepted publickey for leonardo from 192.168.10.25 port 60112 ssh2
2026-11-17 09:30:11 SERVER-FW sshd[4301]: Failed password for user financeiro from 192.168.20.44 port 49120 ssh2
2026-11-17 09:31:05 SERVER-FW sshd[4305]: Accepted password for user financeiro from 192.168.20.44 port 49125 ssh2
2026-11-17 11:42:10 SERVER-FW sshd[4510]: Failed password for root from 45.95.147.202 port 33410 ssh2
2026-11-17 11:42:13 SERVER-FW sshd[4512]: Failed password for root from 45.95.147.202 port 33415 ssh2
2026-11-17 11:42:15 SERVER-FW sshd[4514]: Failed password for invalid user deploy from 45.95.147.202 port 33419 ssh2
2026-11-17 11:42:18 SERVER-FW sshd[4518]: Failed password for invalid user postgres from 45.95.147.202 port 33422 ssh2
"""


def extrair_falhas_autenticacao(conteudo_log: str) -> dict:
    """
    Utiliza expressões regulares (Regex) para extrair IPs e usuários
    envolvidos em falhas de autenticação nos logs do sistema.
    """
    padrao_falha = re.compile(
        r"Failed password for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    ips_suspeitos = Counter()
    usuarios_visados = Counter()

    for linha in conteudo_log.strip().splitlines():
        match = padrao_falha.search(linha)
        if match:
            ips_suspeitos[match.group("ip")] += 1
            usuarios_visados[match.group("usuario")] += 1

    return {
        "ips_falhas": ips_suspeitos,
        "usuarios_visados": usuarios_visados
    }


def gerar_relatorio_triagem_ia(analise: dict) -> str:
    """
    Consolida os indicadores de ameaça e gera uma análise de resposta a incidentes
    (estrutura pronta para integração com APIs de LLMs como Gemini/OpenAI).
    """
    atacantes = {
        ip: qtd for ip, qtd in analise["ips_falhas"].items()
        if qtd >= LIMITE_TENTATIVAS_SUSPEITAS
    }

    data_execucao = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    relatorio = [
        "=" * 70,
        f"RELATÓRIO DE AUDITORIA DE SEGURANÇA & TRIAGEM AIOps - {data_execucao}",
        "=" * 70,
        f"Total de falhas de login analisadas: {sum(analise['ips_falhas'].values())}",
        f"IPs acima do limite de tolerância (>={LIMITE_TENTATIVAS_SUSPEITAS} falhas): {len(atacantes)}\n",
        "1. ORIGENS DE POSSÍVEL ATAQUE DE FORÇA BRUTA (BRUTE FORCE):"
    ]

    if not atacantes:
        relatorio.append("   Nenhum comportamento anômalo crítico detectado.")
    else:
        for ip, qtd in atacantes.items():
            relatorio.append(f"   [ALERTA ALTO] IP: {ip} -> {qtd} tentativas falhas consecutivas")

    relatorio.append("\n2. CONTAS MAIS VISADAS:")
    for usuario, qtd in analise["usuarios_visados"].most_common(5):
        relatorio.append(f"   - Usuário '{usuario}': {qtd} tentativas")

    relatorio.append("\n3. RECOMENDAÇÕES DE MITIGAÇÃO (RESPOSTA A INCIDENTES):")
    relatorio.append("   [Ação Imediata] Bloquear os IPs ofensores na ACL do Firewall de Borda / iptables.")
    relatorio.append("   [Hardening] Desabilitar login direto via root (PermitRootLogin no) no sshd_config.")
    relatorio.append("   [Automação] Ativar Fail2Ban para banimento dinâmico após 3 falhas de autenticação.")
    relatorio.append("=" * 70)

    return "\n".join(relatorio)


if __name__ == "__main__":
    resultado_extracao = extrair_falhas_autenticacao(LOGS_AUTENTICACAO)
    relatorio_final = gerar_relatorio_triagem_ia(resultado_extracao)
    print(relatorio_final)

    # Exporta evidência estruturada em JSON para integração com SIEM / Webhook / LLM
    evidencia_json = {
        "timestamp": datetime.now().isoformat(),
        "ameacas_detectadas": dict(resultado_extracao["ips_falhas"]),
        "usuarios_alvo": dict(resultado_extracao["usuarios_visados"])
    }
    with open("evidencia_seguranca.json", "w", encoding="utf-8") as f:
        json.dump(evidencia_json, f, indent=4, ensure_ascii=False)
