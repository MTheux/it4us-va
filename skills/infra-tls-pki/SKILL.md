---
name: infra-tls-pki
description: "Analisar evidências TLS e PKI fornecidas ou coletadas por verificadores autorizados, distinguindo configuração de impacto."
---

# TLS e PKI

Use quando houver evidência TLS/PKI associada a um ativo dentro do escopo. O perfil VA aprofundado coleta `ssl-cert` em serviços observados; não avalia a configuração completa de TLS ou AD CS.

1. Exija host/IP, porta, SNI usado, horário, origem, ferramenta e saída bruta ou recibo. Sem SNI, ressalve ambiguidades de certificado.
2. Separe certificado expirado, cadeia incompleta, nome divergente, protocolo/cifra legados e configuração de trust. Registre a condição observada, sem inferir interceptação real.
3. Para AD CS/PKI, avalie somente inventário e evidência fornecidos; não faça enrollment, emissão ou alteração de templates sem escopo específico.
4. Atribua severidade conforme função do serviço, exposição e impacto demonstrado. Recomendação deve apontar configuração e forma de reteste.
5. Marque `não testado` se a campanha trouxe apenas porta aberta ou banner.

**Saída:** `ativo | condição | evidência | impacto plausível | confiança | correção | reteste`. Não apresente esta skill como scanner TLS ativo.
