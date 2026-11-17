# 🛡️ Auditoria de Logs de Segurança e Triagem Inteligente (Python + Cibersegurança + IA)

Ferramenta desenvolvida em **Python** para análise automatizada de logs de autenticação de servidores e firewalls, detecção de ataques de força bruta (*Brute Force*) e geração de relatórios estruturados para resposta a incidentes (**SOC / AIOps**).

---

## 🎯 Contexto e Problema Resolvido
Servidores expostos ou mal segmentados sofrem milhares de tentativas automatizadas de login diariamente. Analisar arquivos de log manualmente (`auth.log`, eventos de firewall) consome tempo valioso da equipe de Infraestrutura.

Este projeto automatiza a primeira camada de defesa e triagem:
1. **Parsing com Expressões Regulares (`re`):** Lê logs brutos de autenticação e extrai IPs de origem e contas de usuário atacadas.
2. **Detecção de Anomalias:** Filtra endereços IP que ultrapassam o limiar configurado de falhas consecutivas.
3. **Saída Estruturada (`JSON` + Relatório Executivo):** Gera evidências prontas para consumo por APIs de Inteligência Artificial (LLMs) ou sistemas SIEM, sugerindo ações imediatas de mitigação (ACLs, Fail2Ban e Hardening SSH).

---

## 🛠️ Conceitos Aplicados
* **Cibersegurança & Hardening:** Identificação de padrões de *Brute Force*, proteção de contas privilegiadas (`root`, `admin`) e bloqueio em nível de ACL/Firewall.
* **Python & Regex:** Manipulação eficiente de textos, estruturas `Counter` e serialização de evidências em `JSON`.
* **Preparação para AIOps / IA:** Arquitetura modular desenhada para enviar o payload JSON de anomalias a modelos de linguagem visando classificação automática de severidade e abertura de ticket no **GLPI**.

---

## 📋 Exemplo de Saída Gerada
```text
======================================================================
RELATÓRIO DE AUDITORIA DE SEGURANÇA & TRIAGEM AIOps - 17/11/2026 14:48:00
======================================================================
Total de falhas de login analisadas: 10
IPs acima do limite de tolerância (>=4 falhas): 2

1. ORIGENS DE POSSÍVEL ATAQUE DE FORÇA BRUTA (BRUTE FORCE):
   [ALERTA ALTO] IP: 185.220.101.45 -> 5 tentativas falhas consecutivas
   [ALERTA ALTO] IP: 45.95.147.202 -> 4 tentativas falhas consecutivas

2. CONTAS MAIS VISADAS:
   - Usuário 'root': 4 tentativas
   - Usuário 'admin': 1 tentativas
```

---
**Desenvolvido por:** [Leonardo de Freitas Pintar](https://github.com/leopintar) — *Engenheiro de Computação | Infraestrutura, Segurança & Automação*
