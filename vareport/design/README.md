# Design VA da IT4US (SysReptor)

Design de **Avaliação de Vulnerabilidades (VA)** derivado do Design de pentest
`IT4us Padrão Pentest` (`3ff2811b-…`). VA, não pentest: os achados param na
condição observada + evidência read-only, sem passo-a-passo de exploração.

## Gerar / atualizar

```bash
export SYSREPTOR_API_TOKEN=...        # token do SysReptor
export SYSREPTOR_URL=http://127.0.0.1:8000
python3 build_va_design.py            # idempotente (cópia nativa + ajustes VA)
# imprime: IT4US_SYSREPTOR_DESIGN_ID=<uuid>
```

O script usa o **copy nativo** do SysReptor (não altera o design base), renomeia
para `IT4US Padrão VA — Avaliação de Vulnerabilidades` e aplica trocas de rótulo
seguras (prosa PT-BR): "Teste de Intrusão"→"Avaliação de Vulnerabilidades",
"Prova de Conceito/PoC"→"Evidência da condição", "pentest"→"avaliação (VA)".
Idempotente por nome: rodar de novo reaplica os ajustes no mesmo design.

`va_design.json` é o export versionado do design resultante.

## Design atual

- **IT4US_SYSREPTOR_DESIGN_ID** = `c0c686ae-e716-428a-8183-f99a04e9f3e2`
- Alimenta `Config.DesignID` (env `IT4US_SYSREPTOR_DESIGN_ID`) no `it4us report`.

## Refino humano pendente (UI do SysReptor) — NÃO automatizado

As trocas de rótulo são seguras, mas o reenquadramento **estrutural** do template
é trabalho de design que deve ser revisado na UI, por ser template de cliente:

1. Adicionar a seção **"Inventário e exposição por ativo"** (descoberta nmap,
   TLS, PKI/ADCS, AD, shares, CVE) — hoje herdada do layout de pentest.
2. Remover narrativa de ataque / kill-chain do `report_template`.
3. Revisar textos-padrão de metodologia para "não-intrusiva".

Verificado: projeto de teste criado a partir deste design renderiza PDF via
`POST /generate/` (200, `application/pdf`); `GET /check/` só acusa warnings
benignos de metadados não preenchidos (não bloqueiam o rascunho).
