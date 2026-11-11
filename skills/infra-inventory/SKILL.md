---
name: infra-inventory
description: "Inventariar ativos de infraestrutura e correlacionar hosts, portas e serviços de campanhas VA autorizadas, sem transformar observações em vulnerabilidades."
---

# Inventário de infraestrutura

Use quando o SOC pedir cobertura de IPs, CIDRs, hosts, portas ou serviços.

1. Leia a tarefa, o escopo exato, exclusões, janela, aprovador e orçamento. Se algum limite faltar, peça definição antes de execução ativa.
2. Compare os alvos expandidos do plano com o escopo autorizado. Não inclua destinos descobertos fora do escopo.
3. Use os recibos de Execuções VA para montar a matriz `alvo | porta | protocolo | serviço | versão observada | origem | horário | estado`.
4. Separe `não testado`, `fechado`, `filtrado` e `aberto`. Ausência de resposta não prova ausência de serviço.
5. Registre a cobertura e os limites do scan; não crie achado de vulnerabilidade por porta aberta ou banner.

O scanner local usa Nmap TCP connect e detecção de serviço. Perfis comuns, 1–1000, 1–65535 e portas customizadas são escolhidos no formulário, sujeitos ao orçamento do plano.
