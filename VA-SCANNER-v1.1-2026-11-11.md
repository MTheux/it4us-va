# IT4US VA Scanner v1.1 — 2026-11-11

## Fluxo do SOC

1. Cadastre uma tarefa e o escopo do cliente.
2. Em **Execuções VA**, informe IPs literais ou ranges CIDR, portas TCP, responsável pela autorização e fim da janela.
3. Valide o plano. A tela mostra os IPs expandidos antes de liberar o início da campanha.
4. O worker instalado na rede do cliente executa Nmap TCP connect e identificação de serviços. O progresso por host aparece na tela; **Interromper** cancela o processo.
5. Cada serviço identificado entra na tarefa como candidato pendente. O SOC revisa em **Achados**. O Chat permanece disponível para apoio, mas não é necessário para iniciar o scan.

O LLM e o MCP são opcionais para o discovery. O agente pode apoiar a investigação dos candidatos na tarefa, mas a v1.1 não dispara validações adicionais automaticamente nem promove candidatos a vulnerabilidades confirmadas.

## Execução e limites

- IPs e CIDRs são expandidos no plano; hostnames não são resolvidos. Há um limite inicial de 4.096 IPs expandidos e 1.000 portas TCP por campanha.
- O scanner usa argumentos fixos de Nmap (`-sT -sV -Pn -n`); não executa NSE, exploração, login, brute force ou movimento lateral.
- Uma campanha por worker de cada vez. A janela de expiração interrompe a execução; falhas de um host não apagam os resultados de outros.
- Recibos JSON ficam em `data/va-runs/` com permissão `0600`. O histórico mostra campanhas concluídas, parciais, canceladas e interrompidas. Os candidatos são gravados no PostgreSQL vinculados à tarefa.
- A API e a interface exigem autenticação. O operador deve confirmar escopo, janela, origem de rede e capacidade antes de iniciar a campanha no ambiente do cliente.

## Ainda não implementado

Scans autenticados, feed de vulnerabilidades, checks específicos de TLS/SMB/AD/PKI, agendamento, comparação de campanhas, identificação estável de achados entre execuções e validação autônoma pelo agente. Esta versão ainda não tem cobertura equivalente ao Greenbone.

O comando CLI de v1.0 continua disponível para operações a partir do terminal; veja [VA-SCANNER-v1.0-2026-11-11.md](VA-SCANNER-v1.0-2026-11-11.md).
