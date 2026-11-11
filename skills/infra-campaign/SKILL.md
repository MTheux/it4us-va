---
name: infra-campaign
description: "Orquestrar campanha VA em fases observáveis: pré-voo, discovery, hipóteses, triagem, revisão e encerramento."
---

# Ciclo de campanha VA

Use quando o SOC quiser conduzir uma campanha de ponta a ponta. Adapte o ciclo de raciocínio do Draxen ao motor disponível no IT4US VA, sem supor que uma skill seja um scanner.

1. **Escopo:** carregue `infra-preflight`; registre alvo, autorização, janela e orçamento. Bloqueie execução se algum gate necessário falhar.
2. **Observar:** revise o plano; após a ação VA aprovada, acompanhe `run_id`, progresso, erros, cancelamento e recibo. Não acrescente IPs descobertos.
3. **Hipótese:** use `infra-inventory`, `infra-service-triage` e `infra-cve-triage` para separar fatos, exposição e candidatos.
4. **Verificar:** proponha a menor checagem autorizada que diferenciaria a hipótese da linha de base. Sem check disponível, mantenha `precisa validar`.
5. **Revisar:** aplique `infra-review` e `infra-coverage`; indique falsos positivos, lacunas, impacto e responsável. O analista decide a promoção do achado.
6. **Aprender:** compare com campanha anterior somente em escopo/perfil equivalentes; registre o que mudou e o que permanece incerto. Proponha `infra-retest` após correção.

**Saída:** plano, recibo, matriz de cobertura, candidatos, decisão do SOC e próximos passos. O motor integrado faz TCP connect/service detection e correlação NVD. O perfil aprofundado executa `ssl-cert` e `smb2-security-mode` em serviços observados, com limite de 16 IPs e 32 portas relevantes por IP. Não faz exploração, login ou validação universal de CVE.
