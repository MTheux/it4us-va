---
name: infra-exposure
description: "Analisar exposição de interfaces administrativas, bancos, caches e filas observados em campanhas de infraestrutura."
---

# Exposição de serviços

Use após `infra-inventory` quando um serviço possa ampliar a superfície de ataque.

1. Vincule IP, porta, protocolo, serviço e versão ao recibo da campanha. Registre de qual rede o worker observou o acesso.
2. Compare com arquitetura e política esperadas: internet, VPN, rede de gestão, segmento interno. Sem topologia, classifique a origem da exposição como desconhecida.
3. Priorize interfaces de administração, banco de dados, cache, fila e painel de observabilidade com base em função e criticidade do ativo.
4. Faça hipótese de risco por serviço: acesso indevido possível, controle de rede ausente ou superfície inesperada. Não declare acesso não autenticado por banner ou porta aberta.
5. Recomende redução de exposição, segmentação, ACL, autenticação forte e monitoramento específicos. Proponha validação apenas com autorização para o método.

**Saída:** `ativo | serviço | origem observada | exposição esperada | evidência | confiança | ação`. Não testar credenciais padrão, enumerar dados ou executar exploit automaticamente.
