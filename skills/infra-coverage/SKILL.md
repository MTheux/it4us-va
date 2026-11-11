---
name: infra-coverage
description: "Medir cobertura real e lacunas de campanhas VA por IP, porta e verificação, com denominadores e motivos de bloqueio."
---

# Cobertura da campanha

Use antes de declarar uma campanha concluída. Uma execução concluída pode ter cobertura parcial.

1. Tome o plano autorizado como denominador: IPs expandidos e portas planejadas. Não use somente hosts que responderam.
2. Leia o recibo e separe `concluído`, `falhou`, `interrompido`, `fora da janela`, `não testado` e `fora de escopo`.
3. Calcule cobertura de discovery e, separadamente, de correlação CVE. Falha da NVD, CPE impreciso, limite atingido e regra complexa deixam CVE `inconclusivo`, não `sem vulnerabilidades`.
4. Identifique segmentos ou classes de serviço sem avaliação e diga o que exigiria novo plano ou ferramenta dedicada.
5. Compare campanhas somente com mesmo escopo, origem e perfil; descreva diferenças antes de afirmar melhoria ou regressão.

**Saída:** `planejado | executado | falhou | não testado | cobertura | lacuna`, com percentuais e denominadores. Nunca conclua ausência de risco a partir de silêncio de rede.
