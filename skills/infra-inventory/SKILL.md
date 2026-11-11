---
name: infra-inventory
description: "Medir cobertura de IPs, portas e serviços de campanhas VA, vinculando cada observação ao recibo e ao escopo autorizado."
---

# Inventário de infraestrutura

Use na fase **observar** do ciclo operacional: escopo → plano → execução → evidência → revisão.

1. Leia a tarefa e o plano da campanha. Registre IPs/CIDRs autorizados, exclusões, portas, aprovador, expiração e origem do worker. Se faltar um limite necessário, pare antes de execução ativa.
2. Compare a lista expandida do plano com as regras da tarefa. IP descoberto fora dessa lista é contexto, nunca um novo alvo automático.
3. Leia o recibo da execução VA e produza `IP | porta | protocolo | serviço | versão/CPE | confiança | estado | horário | run_id`. Aponte a evidência de cada linha.
4. Conte alvos planejados, concluídos, falhos e não executados. Marque `aberto`, `fechado`, `filtrado`, `falhou` ou `não testado` sem converter timeout em resultado negativo.
5. Compare com inventário anterior somente se as duas campanhas tiverem escopo e perfis comparáveis. Destaque mudanças como hipóteses para revisão.

**Saída:** matriz de inventário, cobertura com denominador explícito e lacunas. Porta aberta e banner são observações, não vulnerabilidades. O scanner integrado usa TCP connect e identificação de serviço; não faz UDP nem valida CVE por exploração.
