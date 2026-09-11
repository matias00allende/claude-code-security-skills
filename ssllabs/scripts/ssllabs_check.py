#!/usr/bin/env python
"""
Wrapper de la API SSL Labs v4 (Qualys) para verificaciones de seguridad TLS/SSL
en despliegues de sistemas web publicos.

Uso:
    python ssllabs_check.py --register --first NOMBRE --last APELLIDO --email correo@tuorganizacion.com --org "Mi Organizacion" --restrict-to "tuorganizacion.com,tuorganizacion.net"
    python ssllabs_check.py --host ejemplo.com
    python ssllabs_check.py --host a.ejemplo.com --host b.ejemplo.com --json salida.json
    python ssllabs_check.py --host ejemplo.com --from-cache --max-age 24

Documentacion oficial de la API:
    https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md

Requiere registro previo (una sola vez por correo) via --register. El correo
registrado se guarda localmente en ~/.claude/ssllabs_config.json y se reutiliza
como header 'email' en cada llamada subsiguiente. --restrict-to guarda ademas
una lista de dominios propios: por defecto, solo esos dominios se pueden
evaluar sin pasar --allow-any-domain (para evitar escanear por error un
dominio de un tercero sin autorización).
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.ssllabs.com/api/v4"
CONFIG_PATH = os.path.join(
    os.environ.get("USERPROFILE") or os.path.expanduser("~"),
    ".claude",
    "ssllabs_config.json",
)

TLS_DEBILES = {"TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0"}


def cargar_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def guardar_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def registrar(first, last, email, org, restrict_to):
    if any(dom in email.lower() for dom in ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com")):
        print("ERROR: la API v4 exige un correo de dominio propio/institucional (no Gmail/Yahoo/Hotmail/Outlook).", file=sys.stderr)
        sys.exit(1)

    body = json.dumps({
        "firstName": first,
        "lastName": last,
        "email": email,
        "organization": org,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{API_BASE}/register",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"ERROR registrando ({e.code}): {e.read().decode('utf-8', 'ignore')}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(data, indent=2, ensure_ascii=False))
    if data.get("status") == "success" or "success" in str(data.get("message", "")).lower():
        cfg = {"email": email, "organization": org}
        if restrict_to:
            cfg["allowed_domains"] = [d.strip() for d in restrict_to.split(",") if d.strip()]
        guardar_config(cfg)
        print(f"\nCorreo '{email}' guardado en {CONFIG_PATH}. Ya puedes usar --host.")
    else:
        print("\nAVISO: la respuesta no confirma exito explicitamente. Revisa el mensaje anterior.", file=sys.stderr)


def llamar_api(path, params, email, reintentos=5):
    qs = urllib.parse.urlencode(params)
    url = f"{API_BASE}/{path}?{qs}"
    espera = 5

    for intento in range(reintentos):
        req = urllib.request.Request(url, headers={"email": email})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                max_a = resp.headers.get("X-Max-Assessments")
                cur_a = resp.headers.get("X-Current-Assessments")
                return data, max_a, cur_a
        except urllib.error.HTTPError as e:
            if e.code == 441:
                print("ERROR 441: correo no registrado. Ejecuta primero --register.", file=sys.stderr)
                sys.exit(1)
            if e.code == 429:
                print(f"Rate limit (429). Esperando {espera}s antes de reintentar...", file=sys.stderr)
                time.sleep(espera)
                espera = min(espera * 2, 60)
                continue
            if e.code in (503, 529):
                print(f"Servicio no disponible/sobrecargado ({e.code}). Esperando {espera}s...", file=sys.stderr)
                time.sleep(espera)
                espera = min(espera * 2, 120)
                continue
            print(f"ERROR HTTP {e.code}: {e.read().decode('utf-8', 'ignore')}", file=sys.stderr)
            sys.exit(1)
    print("ERROR: se agotaron los reintentos por rate limiting/sobrecarga.", file=sys.stderr)
    sys.exit(1)


def analizar_host(host, email, from_cache, max_age, publish, ignore_mismatch):
    params = {
        "host": host,
        "all": "done",
        "publish": "on" if publish else "off",
    }
    if ignore_mismatch:
        params["ignoreMismatch"] = "on"

    if from_cache:
        params["fromCache"] = "on"
        if max_age:
            params["maxAge"] = str(max_age)
    else:
        params["startNew"] = "on"

    data, max_a, cur_a = llamar_api("analyze", params, email)
    if max_a is not None:
        print(f"[{host}] limites API - max: {max_a}, en curso: {cur_a}", file=sys.stderr)

    # Tras el primer llamado con startNew=on, las siguientes consultas de
    # polling deben omitir startNew (solo se usa para forzar una vez).
    params.pop("startNew", None)

    espera = 8
    while data.get("status") not in ("READY", "ERROR"):
        time.sleep(espera)
        espera = min(espera + 2, 15)
        data, _, _ = llamar_api("analyze", params, email)
        print(f"[{host}] estado: {data.get('status')} ...", file=sys.stderr)

    return data


def resumir_endpoint(ep):
    grade = ep.get("grade", "?")
    warn = " (con advertencias)" if ep.get("hasWarnings") else ""
    lineas = [f"  IP {ep.get('ipAddress', '?')}: grado {grade}{warn}"]

    details = ep.get("details") or {}
    protocolos = details.get("protocols") or []
    nombres_protocolos = [f"{p.get('name')} {p.get('version')}" for p in protocolos]
    debiles = [p for p in nombres_protocolos if p in TLS_DEBILES]
    if debiles:
        lineas.append(f"    ALERTA protocolos obsoletos habilitados: {', '.join(debiles)}")

    vulns = {
        "heartbleed": "Heartbleed",
        "poodle": "POODLE",
        "freak": "FREAK",
        "logjam": "Logjam",
        "drownVulnerable": "DROWN",
        "ticketbleed": "Ticketbleed",
        "bleichenbacher": "ROBOT/Bleichenbacher",
    }
    hallados = [nombre for clave, nombre in vulns.items() if details.get(clave) is True]
    if hallados:
        lineas.append(f"    CRITICO vulnerabilidades detectadas: {', '.join(hallados)}")

    if details.get("forwardSecrecy", 0) == 0:
        lineas.append("    ALERTA sin Forward Secrecy")

    hsts = details.get("hstsPolicy") or {}
    if hsts.get("status") != "present":
        lineas.append("    AVISO sin HSTS activo")

    return "\n".join(lineas)


def resumir_host(data):
    print(f"\n== {data.get('host')} ==")
    print(f"Estado: {data.get('status')}")
    if data.get("status") == "ERROR":
        print(f"Mensaje: {data.get('statusMessage')}")
        return

    certs = data.get("certs") or []
    for cert in certs:
        not_after = cert.get("notAfter")
        if not_after is None:
            continue
        dias = int((not_after / 1000 - time.time()) / 86400)
        if dias < 0:
            aviso = f" -- VENCIDO hace {-dias} dias (raiz/intermedio legado, no invalida la cadena vigente si hay otro camino de confianza activo)"
        elif dias < 30:
            aviso = " -- VENCE PRONTO"
        else:
            aviso = ""
        print(f"Certificado '{cert.get('subject', '?')}' vence en {dias} dias{aviso}")

    for ep in data.get("endpoints") or []:
        print(resumir_endpoint(ep))


def main():
    ap = argparse.ArgumentParser(description="Verificacion de seguridad TLS/SSL via SSL Labs API v4")
    ap.add_argument("--register", action="store_true", help="Registrar correo propio/institucional (una vez)")
    ap.add_argument("--first", help="Nombre (con --register)")
    ap.add_argument("--last", help="Apellido (con --register)")
    ap.add_argument("--email", help="Correo propio/institucional (con --register)")
    ap.add_argument("--org", help="Organizacion (con --register)")
    ap.add_argument("--restrict-to", help="Con --register: lista de dominios propios separados por coma. Sin --allow-any-domain, solo estos hosts se podrán evaluar")

    ap.add_argument("--host", action="append", default=[], help="Host a evaluar (repetible)")
    ap.add_argument("--from-cache", action="store_true", help="Usar resultado en cache si existe")
    ap.add_argument("--max-age", type=int, default=None, help="Edad máxima en horas para el cache")
    ap.add_argument("--publish", action="store_true", help="Publicar resultado en boards públicos de SSL Labs (NO usar salvo autorización explícita)")
    ap.add_argument("--ignore-mismatch", action="store_true", help="Ignorar discrepancia certificado/hostname")
    ap.add_argument("--json", help="Guardar resultado crudo (todos los hosts) en este archivo")
    ap.add_argument("--allow-any-domain", action="store_true", help="Permitir hosts fuera de la lista registrada con --restrict-to")

    args = ap.parse_args()

    if args.register:
        faltantes = [n for n, v in (("--first", args.first), ("--last", args.last), ("--email", args.email), ("--org", args.org)) if not v]
        if faltantes:
            print(f"ERROR: faltan parámetros para registro: {', '.join(faltantes)}", file=sys.stderr)
            sys.exit(1)
        registrar(args.first, args.last, args.email, args.org, args.restrict_to)
        return

    cfg = cargar_config()
    email = cfg.get("email")
    if not email:
        print("ERROR: no hay correo registrado. Ejecuta primero --register.", file=sys.stderr)
        sys.exit(1)

    if not args.host:
        print("ERROR: especifica al menos un --host.", file=sys.stderr)
        sys.exit(1)

    if args.publish:
        print("AVISO: --publish expone el resultado en los boards públicos de SSL Labs. Confirma autorización antes de continuar.", file=sys.stderr)

    dominios_permitidos = cfg.get("allowed_domains") or []
    if dominios_permitidos and not args.allow_any_domain:
        for h in args.host:
            if not any(h.endswith(d) for d in dominios_permitidos):
                print(f"ERROR: '{h}' no pertenece a {dominios_permitidos}. Usa --allow-any-domain si es intencional.", file=sys.stderr)
                sys.exit(1)

    resultados = []
    for h in args.host:
        data = analizar_host(h, email, args.from_cache, args.max_age, args.publish, args.ignore_mismatch)
        resultados.append(data)
        resumir_host(data)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(resultados, f, ensure_ascii=False, indent=2)
        print(f"\nResultado crudo guardado en {args.json}")


if __name__ == "__main__":
    main()
