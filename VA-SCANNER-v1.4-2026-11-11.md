# IT4US VA Scanner v1.4 — 2026-11-11

## Navegação e consulta de CVE

**Tarefas** aparece antes de **Execuções VA**. A execução recebe automaticamente o nome da tarefa, sem campo de nome adicional.

**Pesquisar CVE** não exige campanha anterior. Consulta a NVD por ID e mostra descrição e referências públicas marcadas como `Exploit` pela própria NVD, sem baixar ou executar PoCs. GitHub Advisory, EPSS (FIRST) e CISA KEV enriquecem a consulta quando disponíveis; falha dessas fontes é mostrada como indisponibilidade, nunca como ausência de risco. Após a busca, uma campanha concluída pode ser selecionada para comparação de CPE/versão. Correspondência continua sendo candidato, sujeita a patch, backport, configuração e revisão humana.

## VA aprofundado

O worker agora oferece o perfil **Discovery + VA aprofundado**: primeiro executa Nmap TCP connect e identificação de serviço; depois roda somente os scripts NSE `ssl-cert` e `smb2-security-mode` nos serviços relevantes já observados. Os resultados entram no recibo por IP e condições de certificado expirado ou assinatura SMB não obrigatória viram candidatos pendentes. A correlação NVD permanece na etapa final. O perfil aceita até 16 IPs e 32 portas relevantes por IP, usa timeout por host e respeita cancelamento e expiração da campanha. Falha em um check profundo preserva o discovery e marca cobertura parcial.

Isso é execução VA somente de infraestrutura no IT4US, com o ciclo de evidências inspirado no Draxen/ForeSea. Não há execução Web/API nesse fluxo. AD CS, SQL, shares autenticados e outros parsers ForeSea ainda não têm executores governados aqui. Nenhum alvo real foi executado nesta implementação.

## Fontes e limites

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities): consulta por ID e correlação automática de CPE, com limites existentes de paginação e tempo.
- [GitHub Advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories): advisories públicos por ID de CVE, até 5 resultados por busca.
- [FIRST EPSS](https://api.first.org/epss/): score por CVE, usado para priorização, sem provar exploração.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): catálogo de exploração observada, com cache de 6 horas.
- Referências de exploit/PoC: links da NVD, não conteúdo executado ou validado.

Nenhuma campanha contra cliente foi executada durante a implementação. Testes locais cobrem seleção de portas observadas, parsing de evidência, rejeição de resultado fora do alvo, consulta estruturada de CVE e builds.
