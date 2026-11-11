---
name: infra-service-triage
description: "Triar candidatos de serviços de rede com evidência, contexto de ativo e classificação conservadora para revisão do SOC."
---

# Triagem de serviços

Use quando uma campanha VA produzir serviços encontrados.

1. Leia o recibo da campanha e confira alvo, porta, protocolo, serviço, versão inferida e horário.
2. Diferencie identificação confirmada por resposta do serviço de inferência por fingerprint; preserve o nível de confiança.
3. Correlacione com função do ativo, exposição esperada e inventário anterior. Não presuma que o serviço esteja vulnerável.
4. Priorize revisão humana quando houver exposição inesperada, serviço administrativo, versão legada ou mudança de superfície.
5. Produza um candidato com evidência e próximo passo seguro. Use `precisa validar` para qualquer hipótese de vulnerabilidade sem reprodução autorizada.

Não execute autenticação, exploit, enumeração adicional ou alteração de configuração sem escopo e autorização específicos.
