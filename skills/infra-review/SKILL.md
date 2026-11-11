---
name: infra-review
description: "Revisar campanha VA com cobertura, cadeia de evidências, decisão por candidato e plano de correção ou reteste."
---

# Revisão SOC de infraestrutura

Use na fase **revisar**; o agente propõe a decisão, e o analista do SOC a confirma.

1. Reconcilie tarefa, plano, aprovação, janela, orçamento, `run_id`, parâmetros, interrupções e erros. Divergência de escopo torna a conclusão inconclusiva.
2. Separe inventário, exposição, correlação de CVE e validação de impacto. Inclua denominador da cobertura e ativos não testados.
3. Para cada candidato, registre `ativo | hipótese | evidência | confiança | status | lacuna | responsável`. Estados: `confirmado`, `provável`, `inconclusivo`, `descartado`.
4. Exija prova reproduzível para `confirmado`; match NVD, banner, timeout ou HTTP 200/403/502 não bastam. Faça a revisão de falso positivo e de impacto de negócio.
5. Entregue correção específica e critério de reteste por achado confirmado. Para candidatos, entregue próximo passo seguro e pendência explícita.
6. Redija somente dados mínimos; remova tokens, senhas e PII de artefatos e logs compartilhados.

**Saída:** decisão por candidato, cobertura, limitações e plano de correção/reteste. Não declare campanha completa se houve ativos ou checks bloqueados, falhos ou não executados.
