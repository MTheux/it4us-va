# Conexões do SOC · v1.0 · 2026-11-11

Abra **Conexões** no menu (`/system/connections`).

## IA

1. Escolha **Claude API** e cole uma API key da Anthropic, ou escolha **OpenCode local** se a conta já estiver conectada ao serviço OpenCode na mesma máquina.
2. Confira o modelo e clique **Testar e conectar**. O VA faz uma chamada curta ao modelo. Só exibe **Conectado** após receber resposta não vazia; falhas ficam visíveis.
3. Após o teste, o perfil é salvo e ativado. O campo de chave fica vazio ao reabrir; uma chave já salva pode ser retestada sem digitá-la novamente.

A interface não devolve a chave após o cadastro. O perfil é armazenado no PostgreSQL do VA; proteja o banco, os backups e os acessos administrativos. A conexão com uma conta Claude no aplicativo OpenCode local não transfere automaticamente sua credencial para o VA.

## MCP

1. Informe nome, URL HTTPS e, se o servidor aceitar, um Bearer token. Clique **Salvar** e depois **Testar MCP**.
2. A contagem e os nomes das ferramentas vêm de `tools/list` real. Um conector só aparece como **Conectado** depois de uma descoberta bem-sucedida.
3. Marque os agentes que podem usar o conector. Ferramentas externas, inclusive leitura e escrita, passam pelo fluxo de permissão do agente. A prévia direta do painel aceita somente `list_reports` e `get_report` do MCP local de demonstração, com limite de entrada, tempo e saída.

Uma edição limpa a saúde e a lista de ferramentas antigas antes de redescobrir o servidor. A credencial continua salva quando o endpoint não muda; mudar URL, transporte, comando ou argumentos sem informar uma nova credencial limpa o segredo antigo para evitar envio ao novo destino.

O template Atlassian usa `https://mcp.atlassian.com/v2/mcp`. O Rovo MCP usa OAuth 2.1 como método principal; esta versão do painel não implementa o login OAuth. O Bearer token só funciona se a organização Atlassian habilitou esse modo. Sem isso, o teste deve falhar e nenhum acesso a Jira ou Confluence é presumido.

## Demonstração de relatório

Na instalação de demonstração, o conector `soc_demo_reports` é um servidor MCP local de leitura, com dois documentos fictícios. Use **Buscar relatórios**, abra um item e clique **Baixar relatório .md**. O exemplo não contém dados de clientes nem comprova vulnerabilidades. O arquivo `scripts/demo_soc_mcp.py` pode ser removido da configuração de produção.
