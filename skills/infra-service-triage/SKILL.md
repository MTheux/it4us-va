---
name: infra-service-triage
description: "Triar exposições de serviços com hipótese, evidência rastreável e próxima verificação segura para o SOC."
---

# Triagem de serviços

Use após `infra-inventory`, para serviços administrativos, bancos, caches, filas, interfaces de gestão e exposição inesperada.

1. Confira `run_id`, IP, porta, protocolo, horário, resposta observada, fingerprint e confiança. Não infira versão precisa de banner genérico.
2. Formule uma hipótese por serviço: exposição esperada, superfície administrativa, versão possivelmente legada ou mudança desde o último inventário.
3. Consulte a função do ativo e a origem de rede do worker. Acesso observado dessa origem não prova exposição à internet.
4. Registre a verificação mínima necessária. Sem autorização específica, limite-se à evidência já coletada; não teste credenciais padrão, brute force, enumeração de dados ou alteração de configuração.
5. Produza `candidato | evidência | hipótese | confiança | impacto possível | próximo passo | responsável`, com `precisa validar` até haver prova controlada.

**Parada:** alvo fora do escopo, janela expirada, erro repetido ou sinal de impacto operacional. Encaminhe ao SOC. A skill não habilita ferramentas nem eleva permissões do worker.
