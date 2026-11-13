# Análise REA do gerenciador local — v1.0 (2026-11-13)

**Alvo analisado:** binário ELF ARM64 `gvmd` extraído do contêiner local `greenbone-community-edition-gvmd-1`. SHA-256: `38768fc79d341e6816c5d0beae5b7affa5a0cf39748a2e65e03795193ec8cb39`.

**Ferramentas:** REA `rea-agents` 6.9.0 e provider Ghidra 12.1.4. A análise foi estática; o binário não foi executado pelo REA. Os JSONs completos permanecem no diretório local ignorado `dist/rea-analysis/`, sem distribuição do binário ou do feed no GitHub.

## Evidência e decisão de integração

- `inspect-artifact`: Evidence `ev_7ff73cee29a345447b48ac75ee5974df0f2e712ddaf5ee25fd4e07a9bc2f1359`. Identificou o ELF e fixou a identidade do artefato.
- `analyze`: 4.896 procedimentos e 19.911 strings recuperados no binário analisado.
- `search --kind procedures get_info`: encontrou `handle_get_info` em `0x179540`.
- `decompile handle_get_info`: Evidence `ev_8d1521104f853962ac3803bb649e410d02e29be2e2b9d886eb470c9ef3b1d990`. O fluxo decompilado verifica a permissão `get_info`, exige a base SCAP carregada e seleciona `cve_info_count`/`init_cve_info_iterator` para o tipo `cve`. Essa evidência orientou o uso da API GMP autenticada, sem acesso direto à tabela PostgreSQL do motor pelo backend VA.
- `decompile start_task`: Evidence `ev_0be7eb962e80f1f934e79e3e583d0001e30e62d77efa0c71d99aeca8555a906e`. A entrada verifica `acl_user_may("start_task")` e delega a `run_task`; o controle de escopo, portas e tempo do IT4US VA continua no próprio backend antes e durante essa chamada.
- `decompile run_task`: Evidence `ev_6c421430b2c145ed10e6895a5480d9688bfba8cddb0426a866c4e2a2baf318db`. O fluxo observado verifica janela de manutenção, concorrência do scanner, permissões do scanner e do alvo, e inicia um handler de scan separado. São verificações internas do gerenciador; o limite de ativos autorizado pelo cliente é aplicado pelo VA antes de criar e iniciar a tarefa.
- Chamada GMP real `<get_info type="cve" name="CVE-2021-44228" details="1"/>`: resposta `200`, registro com descrição e atualização de feed `2026-11-13T02:15:00.000+0000`, `info_count=424948`.
- Consulta local read-only em `scap.cves`: 424.948 registros; `scap.cpes`: 1.872.266; `scap.cve_references`: 1.373.131. Contagens são um retrato desta instalação, não números fixos do produto.

## Como o VA usa a base

`vascan.GMPCVELookup` consulta a base SCAP via GMP no loopback, com credencial injetada somente no processo. A busca manual de CVE mostra a base local como fonte adicional e usa a descrição local se a NVD estiver indisponível. A correspondência de CPE/versão e a decisão de aplicabilidade continuam conservadoras; a presença de uma CVE no feed não confirma vulnerabilidade em um ativo.

## Limites

O REA analisou o gerenciador e seu caminho de consulta SCAP. Isso não prova cobertura de cada VT nem comportamento de cada regra NASL. A análise do código decompilado é inferência estática, corroborada pela resposta GMP observada. As campanhas continuam limitadas às portas e aos IPs autorizados pelo VA.

Para reproduzir a leitura estática com uma instalação local do [REA](https://github.com/morluto/rea) e Ghidra 12.1.4:

```bash
GHIDRA_INSTALL_DIR=/caminho/ghidra_12.1.4_PUBLIC rea analyze /caminho/gvmd --provider ghidra --format json
GHIDRA_INSTALL_DIR=/caminho/ghidra_12.1.4_PUBLIC rea decompile /caminho/gvmd handle_get_info --provider ghidra --format json
GHIDRA_INSTALL_DIR=/caminho/ghidra_12.1.4_PUBLIC rea decompile /caminho/gvmd start_task --provider ghidra --format json
GHIDRA_INSTALL_DIR=/caminho/ghidra_12.1.4_PUBLIC rea decompile /caminho/gvmd run_task --provider ghidra --format json
```
