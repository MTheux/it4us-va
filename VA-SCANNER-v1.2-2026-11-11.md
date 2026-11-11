# IT4US VA Scanner v1.2 — 2026-11-11

## Fluxo automático após a aprovação do SOC

1. O operador define a tarefa, os IPs/CIDRs, portas TCP, responsável pela autorização e fim da janela. A revisão mostra os IPs expandidos e o total de portas antes do início.
2. O worker executa Nmap TCP connect e identificação de serviços nos IPs revisados. Serviços são gravados no inventário e exposições sensíveis entram em **Achados** como candidatos pendentes.
3. Para cada CPE observado com versão concreta, o worker consulta a API de CVEs da NVD. Compara os critérios CPE e as faixas de versão publicados com o serviço observado. Correspondências possíveis geram candidatos pendentes por IP, porta e CVE, com fonte e critério no campo de evidência.
4. A execução mostra quantos CPEs e CVEs foram consultados, quantos candidatos surgiram e se a cobertura foi completa, parcial, indisponível ou impossível por falta de CPE preciso. O SOC revisa os candidatos e verifica patch/backport e as condições específicas da CVE.

A correlação consulta a NVD; **não envia novas requisições ao alvo**. Ela não prova explorabilidade, impacto, ausência de correção ou vulnerabilidade confirmada. Regras NVD com condições combinadas (`AND`) ou negadas são tratadas como inconclusivas. Um candidato não muda sozinho para o estado confirmado.

## Limites e falhas explícitas

- No máximo **8 CPEs distintos**, **200 registros NVD por consulta**, **40 CVEs avaliadas** e **200 correspondências por campanha automática**; exceder qualquer limite marca cobertura parcial. Dentro da página recebida, as CVEs mais recentes são avaliadas primeiro. As chamadas à NVD são espaçadas em pelo menos 6 segundos e a etapa tem limite de 90 segundos.
- Apenas CPEs informados pelo Nmap com versão concreta são usados. Banner genérico, produto sem versão ou ausência de CPE não gera suposição por texto; a etapa registra que não havia base para busca automática.
- Falha ou indisponibilidade da NVD não apaga o discovery nem produz resultado negativo fictício. O recibo registra indisponibilidade ou cobertura parcial.
- O scanner mantém os argumentos fixos `-sT -sV -Pn -n`, sem NSE, exploit, login, brute force ou movimento lateral. São aceitos até 4.096 IPs expandidos e 1.000 portas personalizadas; o perfil de todas as portas tem orçamento de 4.096.000 combinações IP × porta.
- Uma campanha por worker de cada vez. A janela expirada ou **Interromper** cancela a execução. Os recibos ficam em `data/va-runs/` e os candidatos em PostgreSQL.

## Verificação específica de CVE

A ação **Verificar CVE específica** continua disponível para consultar um ID adicional em uma campanha concluída. A validação de impacto de uma CVE exige um check próprio, seguro e autorizado para aquela falha. Esta versão automatiza a **triagem de aplicabilidade** e a abertura de candidatos, mas não possui um validador universal de CVEs nem promove uma correspondência de versão a vulnerabilidade confirmada.

Para testar um IP de cliente, a equipe precisa ter autorização atual com IP exato, origem de rede, portas, janela, capacidade permitida e contato de parada. Nenhum IP de cliente está incluído no projeto ou nos testes automatizados.
