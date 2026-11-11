# IT4US VA Scanner v1.0 — 2026-11-11

## Fluxo operacional inicial

O SOC cria uma tarefa no IT4US VA e registra uma campanha JSON com os IPs e
portas aprovados para a janela. Um comando executa Nmap TCP connect e detecção
de serviços, grava um recibo privado por host e vincula os candidatos à tarefa.
Os candidatos ficam pendentes para revisão humana ou análise do agente. Uma
porta aberta ou um banner de versão, isoladamente, não confirma vulnerabilidade.

Este comando não inicia exploração, login, brute force ou scripts NSE. O
agente não escolhe flags nem expande a lista de alvos. A campanha é definida
uma vez, sem confirmação individual para cada host.

## Campanha

Exemplo **somente para laboratório local** (`127.0.0.1`):

```json
{
  "name": "laboratorio-local",
  "task_id": 123,
  "approved_by": "operador-soc",
  "expires_at": "2099-01-01T00:00:00Z",
  "targets": ["127.0.0.1"],
  "ports": [22, 80, 443]
}
```

No cliente, o SOC substitui os campos pelos dados da autorização e pelo
inventário acordado. Nesta versão, cada alvo é um IP literal; CIDR e hostname
são rejeitados para que a execução não expanda o alvo implicitamente.

## Executar

Pré-requisitos: Nmap no `PATH`, PostgreSQL configurado como para o backend e
uma tarefa existente na UI. O container do projeto já inclui Nmap. A saída
fica em `data/va-runs/` com arquivo `0600` por padrão.

```bash
go run ./cmd/it4us va scan --campaign /caminho/campanha.json --task-id 123 --dry-run
go run ./cmd/it4us va scan --campaign /caminho/campanha.json --task-id 123
```

Na instalação Docker Compose, coloque o JSON em `data/va-campaign.json`
(volume montado em `/app/data`) e use:

```bash
docker compose exec -T it4us /app/it4us va scan \
  --campaign /app/data/va-campaign.json --task-id 123 --dry-run
docker compose exec -T it4us /app/it4us va scan \
  --campaign /app/data/va-campaign.json --task-id 123
```

O operador deve executar o comando a partir da rede do cliente que alcança os
IPs autorizados. Confira os alvos no `--dry-run` e a rota/endereço de origem na
instalação antes do scan; o container usa a rede definida pelo Docker Compose.

Para validar em laboratório sem PostgreSQL, use `--record-only`: ele executa
o check e grava o recibo, mas não cria ativos ou candidatos na UI.

O segundo comando gera tráfego **somente** para os IPs da campanha. Use-o
apenas depois de confirmar autorização, janela, rede de origem e capacidade.
Se um host falhar, a campanha continua e o processo termina com erro; o JSON
mostra qual host falhou. A saída XML bruta do Nmap não é persistida: o recibo
guarda seu SHA-256, os candidatos normalizados e o estado de cada host.

Após a revisão dos candidatos na UI, somente os achados marcados como
`confirmed` da tarefa entram no rascunho SysReptor:

```bash
go run ./cmd/it4us report --task-id 123 "VA do cliente"
```

## Relação com a ForeSea e o Draxen

A análise ForeSea demonstrou que sinais de serviços, SMB, AD e PKI precisam ser
correlacionados para uma conclusão útil. Este primeiro executor cobre apenas
descoberta TCP/serviços. Os parsers existentes de TLS, shares, PKI, AD, SQL e
CVE ainda precisam de executores e fontes de dados verificadas. O fluxo de
planejamento e revisão por agente do IT4US VA pode consumir os candidatos da
tarefa; execução de checks e classificação confirmada continuam separadas.

## Limitações desta versão

- Sem scans autenticados, feed de vulnerabilidades, agendamento de campanha,
  comparação de campanhas ou cobertura equivalente ao Greenbone.
- Resultados repetidos em campanhas distintas criam candidatos separados;
  ainda não existe identidade estável de achado entre campanhas.
- Falha durante a gravação no banco pode deixar parte dos candidatos salva;
  o comando informa quantos foram gravados.
- O operador deve revisar títulos e severidades do parser Nmap no contexto da
  segmentação do cliente antes de confirmar ou exportar achados.
