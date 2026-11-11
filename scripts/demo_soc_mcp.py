#!/usr/bin/env python3
"""Read-only MCP fixture for the IT4US SOC connection screen.

Contains invented laboratory data only. Do not add customer reports here.
"""

import json
import sys


REPORTS = {
    "lab-va-001": {
        "title": "Relatório de laboratório VA",
        "content": """# Relatório de laboratório VA

Ambiente: 127.0.0.1, serviços sintéticos. Data: 2026-11-11.

## Escopo
Portas 18221/tcp e 18222/tcp em loopback.

## Observações
- FTP simulado: candidato pendente para revisão.
- SSH simulado: serviço inventariado; versão anunciada no banner.
- CVE consultado por CPE: correspondência possível, sem validação de impacto.

## Conclusão
Este documento demonstra o fluxo de consulta e download via MCP. Não é um
relatório de cliente e não confirma vulnerabilidades.
""",
    },
    "soc-review-002": {
        "title": "Checklist de revisão SOC",
        "content": """# Checklist de revisão SOC

1. Confirmar escopo e aprovação da campanha.
2. Revisar recibo, serviço e evidência de cada candidato.
3. Validar CVE por versão, configuração e teste autorizado.
4. Registrar decisão: confirmado, falso positivo ou inconclusivo.
""",
    },
}


TOOLS = [
    {
        "name": "list_reports",
        "description": "Lista relatórios fictícios disponíveis no laboratório SOC.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_report",
        "description": "Lê um relatório fictício pelo ID.",
        "inputSchema": {
            "type": "object",
            "properties": {"report_id": {"type": "string"}},
            "required": ["report_id"],
            "additionalProperties": False,
        },
    },
]


def respond(request):
    method = request.get("method")
    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "it4us-soc-demo", "version": "1.0"},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "list_reports":
            payload = [
                {"id": key, "title": report["title"], "format": "markdown", "demo": True}
                for key, report in REPORTS.items()
            ]
            return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}
        if name == "get_report":
            report = REPORTS.get(args.get("report_id"))
            if report:
                return {"content": [{"type": "text", "text": report["content"]}]}
            return {"content": [{"type": "text", "text": "Relatório não encontrado"}], "isError": True}
        return {"content": [{"type": "text", "text": "Ferramenta desconhecida"}], "isError": True}
    return {}


for line in sys.stdin:
    request = None
    try:
        request = json.loads(line)
        if "id" not in request:
            continue
        payload = {"jsonrpc": "2.0", "id": request["id"], "result": respond(request)}
    except (ValueError, TypeError) as exc:
        payload = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                   "error": {"code": -32600, "message": str(exc)}}
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()
