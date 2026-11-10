#!/usr/bin/env python3
"""Importador idempotente do Design VA da IT4US no SysReptor.

Deriva um Design de Avaliação de Vulnerabilidades (VA) a partir do Design de
pentest da IT4US ("IT4us Padrão Pentest"), via o copy nativo do SysReptor, e
aplica trocas de rótulo seguras (prosa PT-BR) para reenquadrar pentest -> VA.

NÃO altera o design base. Idempotente por nome: se o Design VA já existe, apenas
reaplica os ajustes. O refino profundo (seção "Inventário por ativo", remoção de
kill-chain) é passo humano na UI do SysReptor — ver README.md.

Env: SYSREPTOR_API_TOKEN (obrigatório), SYSREPTOR_URL (default http://127.0.0.1:8000),
     IT4US_BASE_DESIGN_ID (default = IT4us Padrão Pentest).
"""
import os
import sys
import json
import urllib.request

URL = os.environ.get("SYSREPTOR_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("SYSREPTOR_API_TOKEN", "")
BASE_ID = os.environ.get("IT4US_BASE_DESIGN_ID", "3ff2811b-7b89-483f-9bc0-51910bd75aad")
VA_NAME = "IT4US Padrão VA — Avaliação de Vulnerabilidades"

# Trocas de rótulo seguras: prosa PT-BR visível, nunca identificadores/JS.
REPLACEMENTS = [
    ("Teste de Intrusão", "Avaliação de Vulnerabilidades"),
    ("teste de intrusão", "avaliação de vulnerabilidades"),
    ("Teste de intrusão", "Avaliação de vulnerabilidades"),
    ("Prova de Conceito", "Evidência da condição"),
    ("Prova de conceito", "Evidência da condição"),
    ("PoC", "Evidência da condição"),
    ("pentest", "avaliação de vulnerabilidades (VA)"),
]


def api(method, path, body=None, raw=False):
    data = None
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        payload = r.read()
    if raw:
        return payload
    return json.loads(payload) if payload else {}


def swap_strings(obj):
    """Aplica REPLACEMENTS recursivamente só a valores string."""
    if isinstance(obj, str):
        for a, b in REPLACEMENTS:
            obj = obj.replace(a, b)
        return obj
    if isinstance(obj, list):
        return [swap_strings(x) for x in obj]
    if isinstance(obj, dict):
        return {k: swap_strings(v) for k, v in obj.items()}
    return obj


def find_va_design():
    res = api("GET", "/api/v1/projecttypes/?scope=global")
    items = res.get("results", res) if isinstance(res, dict) else res
    for it in items:
        if it.get("name") == VA_NAME:
            return it["id"]
    return None


def main():
    if not TOKEN:
        sys.exit("SYSREPTOR_API_TOKEN não definido")

    va_id = find_va_design()
    if va_id:
        print(f"[=] Design VA já existe: {va_id} — reaplicando ajustes")
    else:
        copied = api("POST", f"/api/v1/projecttypes/{BASE_ID}/copy/", body={"scope": "global"})
        va_id = copied["id"]
        print(f"[+] Design VA criado (cópia de {BASE_ID}): {va_id}")

    # Reenquadramento VA: nome + trocas de rótulo nos campos editáveis.
    base = api("GET", f"/api/v1/projecttypes/{va_id}/")
    patch = {
        "name": VA_NAME,
        "report_sections": swap_strings(base.get("report_sections", [])),
        "finding_fields": swap_strings(base.get("finding_fields", [])),
        "report_template": swap_strings(base.get("report_template", "")),
    }
    api("PATCH", f"/api/v1/projecttypes/{va_id}/", body=patch)
    print(f"[✓] Design VA ajustado: {va_id}")

    # Export versionado (artefato reproduzível).
    out = api("GET", f"/api/v1/projecttypes/{va_id}/")
    for k in ("created", "updated", "usage_count", "lock_info", "copy_of", "source"):
        out.pop(k, None)
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "va_design.json"), "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[✓] va_design.json atualizado (design id {va_id})")
    print(f"\nIT4US_SYSREPTOR_DESIGN_ID={va_id}")


if __name__ == "__main__":
    main()
