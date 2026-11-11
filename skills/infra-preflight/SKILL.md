---
name: infra-preflight
description: "Preparar execução VA com autorização, escopo exato, janela, orçamento, origem do worker e critérios de parada."
---

# Pré-voo de infraestrutura

Use antes de qualquer ação ativa. Esta skill organiza a decisão; o backend precisa continuar aplicando seus próprios controles.

1. Identifique tarefa, responsável, autorização atual, IPs/CIDRs permitidos, exclusões, portas/protocolos, origem do worker, janela e contato de parada. Não use uma aprovação antiga como permissão atual.
2. Compare o plano expandido da campanha com as regras da tarefa. Cada IP deve estar dentro da autorização; a descoberta não amplia escopo.
3. Calcule `IPs × portas`, perfil, tempo máximo e capacidade do alvo. Registre versão do plano, aprovador e expiração no recibo.
4. Verifique disponibilidade do scanner e do armazenamento. Se não houver worker, orçamento ou janela válidos, marque `bloqueado` e descreva o requisito faltante.
5. Defina critérios de interrupção: pedido do responsável, expiração, erro repetido, degradação do serviço ou desvio de escopo.

**Saída:** `pronto | bloqueado`, plano revisado, limites e motivo verificável. Não inicie campanha a partir desta skill; a execução ocorre pela ação VA com validação do servidor.
