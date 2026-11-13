# Motor de VTs local

Este diretório contém uma cópia do Compose oficial da Greenbone Community Edition, obtida em 2026-11-13 de `https://greenbone.github.io/docs/latest/_static/compose.yaml`, e uma sobreposição local para acesso GMP pelo backend. As imagens, o feed e seus avisos de licença pertencem aos respectivos projetos Greenbone. O nome do motor não precisa aparecer na interface SOC, mas a atribuição permanece aqui.

## Iniciar no Mac do SOC

Requisitos: Docker Desktop com aproximadamente 8 GiB de memória disponíveis e espaço para as imagens e o feed. Revise a versão do Compose oficial antes de atualizar imagens em produção.

```bash
docker compose -f deploy/greenbone/compose.upstream.yaml \
  -f deploy/greenbone/compose.bridge.yaml \
  up -d gvmd gmp-bridge
docker compose -f deploy/greenbone/compose.upstream.yaml \
  -f deploy/greenbone/compose.bridge.yaml ps
```

O comando inicia os serviços de dados, PostgreSQL, scanner e gerenciador. Não inicia a interface GSA. A única porta publicada é `127.0.0.1:9390` para o bridge GMP. O primeiro carregamento do feed pode demorar. Depois, execute `scripts/configure-infra-vt-profile.py --password-stdin` com a senha vinda do cofre. Ele cria o perfil `IT4US Infra Only v2` a partir do perfil vazio, seleciona somente as famílias de VT de infraestrutura e verifica `safe_checks=1`. As famílias de aplicação, verificações genéricas, enumeração de produtos, port scanners, brute force e DoS ficam fora do perfil. O discovery Nmap já cuida das portas. Não habilite `IT4US_VA_VT_ENABLED=1` antes desse pré-voo.

A imagem inicial pode criar `admin/admin`. Troque a senha antes de qualquer uso e guarde a nova senha em um cofre; neste Mac ela foi armazenada no Keychain como conta `admin`, serviço `it4us-va-gmp`. Não salve a senha em `.env`, no Compose, em logs ou no repositório. O backend recebe `IT4US_GMP_PASSWORD` somente no ambiente do processo. Configure também:

```text
IT4US_VA_VT_ENABLED=1
IT4US_GMP_ADDR=127.0.0.1:9390
IT4US_GMP_USERNAME=admin
IT4US_GMP_CONFIG_ID=<UUID retornado pelo script de perfil seguro>
IT4US_GMP_SCANNER_ID=<UUID do scanner OpenVAS>
```

O VA aprofundado começa por discovery. Para cada IP, o backend envia ao gerenciador apenas as portas TCP observadas, até 32 por host, em uma tarefa exclusiva, com teto de 15 minutos por host. Uma rechecagem do allow da tarefa ocorre antes do scan e a cada polling; timeout, cancelamento, expiração ou revogação tentam parar a tarefa remota. Uma verificação interrompida deixa a campanha parcial. Resultados permanecem **candidatos pendentes** até revisão do SOC. O XML de cada relatório concluído fica no diretório de artefatos da execução.

O Draxen de infraestrutura roda após a campanha em modo offline, sobre o recibo local. Ele registra o handoff e propostas de validação do `AgentState`/`next_best_action`; nenhuma proposta inicia outra varredura automaticamente. Configure `IT4US_DRAXEN_PYTHON`, `IT4US_DRAXEN_BRIDGE` e `IT4US_DRAXEN_ENGINE_DIR` para o runtime local. O bridge está em `scripts/draxen-va-review.py`.

Para parar sem apagar os volumes:

```bash
docker compose -f deploy/greenbone/compose.upstream.yaml \
  -f deploy/greenbone/compose.bridge.yaml stop
```

Referências: [instalação oficial](https://greenbone.github.io/docs/latest/22.4/container/), [fluxo de atualização do feed](https://greenbone.github.io/docs/latest/22.4/container/workflows.html) e [troubleshooting de configs ausentes](https://greenbone.github.io/docs/latest/22.4/container/troubleshooting.html).

## Base local de CVEs e análise do motor

A pesquisa manual de CVE usa a NVD e, quando o GMP local está configurado, consulta também o feed SCAP do gerenciador. Se a NVD falhar, o registro local ainda pode ser exibido como referência, sem atribuir vulnerabilidade a um ativo. O fluxo e a evidência da análise estática com REA estão em [REA-ANALYSIS-v1.0-2026-11-13.md](REA-ANALYSIS-v1.0-2026-11-13.md).
