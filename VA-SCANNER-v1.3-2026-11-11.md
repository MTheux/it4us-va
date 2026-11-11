# IT4US VA Scanner v1.3 — 2026-11-11

## Skills de infraestrutura

O app inclui dez skills de infraestrutura no fluxo `pré-voo → campanha → inventário → triagem → cobertura → revisão → reteste`. As quatro existentes foram ampliadas; as seis novas cobrem pré-voo, campanha, exposição, TLS/PKI, cobertura e reteste. O painel Skills mostra o fluxo e agrupa essas skills.

As skills orientam o agente a separar fato, hipótese e conclusão. Elas não habilitam scanners, não concedem autorização e não promovem candidatos a achados confirmados. O motor VA atual executa Nmap TCP connect/service detection e correlação NVD; TLS/PKI, AD e checks autenticados dependem de evidência externa ou de um executor específico futuro.

## Escopo de execução VA

O endpoint de plano, o endpoint de início da campanha e o comando `it4us va scan` com persistência exigem pelo menos uma regra `allow` ativa de IP ou CIDR na tarefa. Cada IP expandido deve corresponder a uma regra permitida e não pode corresponder a uma regra `block` global ou da tarefa. Uma campanha mista, com um único IP fora do escopo, é recusada antes de iniciar o scanner. `--record-only` aceita somente loopback para validação de laboratório sem PostgreSQL; `--dry-run` apenas imprime o plano e não envia tráfego.

Tarefas antigas sem regras `allow` precisam receber o escopo da tarefa antes de iniciar uma nova campanha. O nome do aprovador e a expiração no JSON da campanha continuam obrigatórios, mas não substituem o allowlist.

## Validação e limites

O teste isolado cobre CIDR permitido, campanha mista, allowlist desabilitado e bloqueio explícito. O parser carregou todas as skills e o build estático da interface passou. Nenhum ativo externo foi testado. A execução autenticada de campanha e a revisão humana dos candidatos continuam necessárias para validar o fluxo operacional de ponta a ponta.
