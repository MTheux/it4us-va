---
name: infra-retest
description: "Planejar e revisar reteste de achados de infraestrutura por ativo e condição, com evidência comparável e status honesto."
---

# Reteste de infraestrutura

Use após o responsável informar uma correção. Reteste é uma nova ação com autorização e janela próprias.

1. Extraia do achado original IP, porta, condição, evidência, impacto e critério de correção. Não trate uma CVE candidata como falha confirmada.
2. Verifique nova autorização, escopo, origem do worker, janela e método permitido; use `infra-preflight`.
3. Planeje a menor observação comparável à original. Registre mudanças de topologia, perfil ou ferramenta que prejudiquem comparação.
4. Compare evidência anterior e atual por ativo e condição. `corrigido` exige que a condição não se reproduza por método válido; timeout, 403, 404 ou 502 isolado é `inconclusivo`.
5. Registre `corrigido`, `persistente`, `parcial`, `inconclusivo` ou `não testado`, com recibo, horário e próxima ação.

**Saída:** matriz por achado e endpoint/serviço, evidência antes/depois, status e limite. Não feche achado automaticamente sem revisão humana.
