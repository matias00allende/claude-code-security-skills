---
name: ssllabs
description: >
  Ejecuta verificación de seguridad TLS/SSL de un dominio público usando la API
  SSL Labs v4 de Qualys, entregando grado (A+ a F), protocolos obsoletos,
  vulnerabilidades conocidas (Heartbleed, POODLE, FREAK, ROBOT), estado de
  Forward Secrecy, HSTS y vencimiento de certificado. Usar cuando el usuario
  diga "ssllabs", "verifica el TLS de", "revisa el certificado de", "que grado
  SSL tiene", "escanea SSL de", "audita el HTTPS de", "checkeo TLS", o como
  parte de auditorias de seguridad de sistemas web con exposicion publica. No
  usar para servidores sin exposicion publica a internet (la API de SSL Labs
  no puede alcanzarlos) ni para escaneos de dominios de terceros sin
  autorización.
model: sonnet
disable-model-invocation: false
allowed-tools: Read Bash
---

# SSL Labs - Verificación de seguridad TLS/SSL

Verifica el despliegue TLS/SSL de: **$ARGUMENTS**

Wrapper: `scripts/ssllabs_check.py` (incluido en esta skill). Documentación oficial de la API: `https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md`.

---

## Alcance y restricciones (leer antes de ejecutar)

- Solo aplica a **hosts con exposición pública a internet** resolubles por SSL Labs (servidores web, balanceadores, CDN). No sirve para servidores internos/on-prem sin publicación externa - para esos casos usar `openssl s_client` local o la skill `auditar` de esta colección.
- El script solo evalúa, por defecto, los dominios que tú mismo declares como propios (ver `--restrict-to` en Paso 0). Para evaluar un dominio de terceros (ej. un proveedor contratado) se requiere levantar esa restricción explícitamente y tener **confirmación de que hay autorización o interés legítimo** (ej. debida diligencia de un proveedor).
- **Nunca usar `--publish`** salvo que se pida explícitamente: expone el resultado (incluyendo IP, grado y detalle de vulnerabilidades) en los boards públicos de SSL Labs, visibles por cualquiera.
- Cada evaluación nueva (`startNew=on`) tarda un mínimo de ~60 segundos; el script hace polling automático. No lanzar evaluaciones repetidas del mismo host en paralelo - la API limita evaluaciones concurrentes por cliente (headers `X-Max-Assessments` / `X-Current-Assessments`).
- Regla de uso de la API (Qualys): gratuita para que operadores prueben **su propia infraestructura**. Uso comercial o de terceros sin relación requiere permiso explícito de Qualys.

---

## Paso 0 - Registro (una sola vez por correo)

Antes del primer uso, verificar si ya existe registro:

```bash
python -c "import json,os; p=os.path.join(os.environ.get('USERPROFILE') or os.path.expanduser('~'),'.claude','ssllabs_config.json'); print(json.load(open(p, encoding='utf-8')) if os.path.exists(p) else 'NO_REGISTRADO')"
```

Si devuelve `NO_REGISTRADO`, pedir al usuario nombre, apellido, correo de su organización
(la API v4 rechaza Gmail/Yahoo/Hotmail/Outlook) y opcionalmente los dominios propios que se van
a evaluar habitualmente, luego ejecutar:

```bash
python scripts/ssllabs_check.py --register --first "NOMBRE" --last "APELLIDO" \
  --email "correo@tuorganizacion.com" --org "Nombre de tu Organizacion"
```

El correo queda guardado en `~/.claude/ssllabs_config.json` y se reutiliza automáticamente en llamadas futuras (header `email`). No repetir el registro salvo que cambie el correo.

Para restringir por defecto los hosts evaluables a tus propios dominios (recomendado, evita escanear por error un dominio de terceros), agrega `--restrict-to`:

```bash
python scripts/ssllabs_check.py --register --first "NOMBRE" --last "APELLIDO" \
  --email "correo@tuorganizacion.com" --org "Nombre de tu Organizacion" \
  --restrict-to "tuorganizacion.com,tuorganizacion.net"
```

---

## Paso 1 - Ejecutar la evaluación

```bash
# Evaluación nueva (recomendado para verificación de despliegue reciente)
python scripts/ssllabs_check.py --host <host>

# Varios hosts en una sola corrida
python scripts/ssllabs_check.py --host a.ejemplo.com --host b.ejemplo.com

# Reutilizar resultado en cache si hay uno de menos de N horas (mas rapido, no re-escanea)
python scripts/ssllabs_check.py --host <host> --from-cache --max-age 24

# Guardar el JSON crudo completo para adjuntar como evidencia en el informe de auditoria
python scripts/ssllabs_check.py --host <host> --json evidencia_ssllabs_<host>.json

# Evaluar un host fuera de los dominios restringidos en el registro (requiere confirmar autorización)
python scripts/ssllabs_check.py --host proveedor-externo.com --allow-any-domain
```

El script hace polling automático (estados `DNS` → `IN_PROGRESS` → `READY`/`ERROR`), respeta rate limiting (backoff en 429/503/529) y al finalizar imprime un resumen legible por endpoint IP:

- Grado (A+ a F, T = sin confianza, M = mismatch de nombre)
- Protocolos obsoletos habilitados (TLS 1.0/1.1, SSL 2.0/3.0)
- Vulnerabilidades críticas detectadas (Heartbleed, POODLE, FREAK, Logjam, DROWN, Ticketbleed, ROBOT)
- Ausencia de Forward Secrecy
- Ausencia de HSTS
- Días hasta vencimiento de cada certificado de la cadena (VENCE PRONTO si < 30 días; VENCIDO si ya pasó - frecuente en raíces legadas cruzadas de la CA, no invalida la cadena si hay otro camino de confianza vigente)

## Paso 2 - Interpretar resultado en el contexto de auditoría

Traducir el resultado del script a formato de hallazgo (compatible con la skill `auditar`):

| Señal del script | Severidad sugerida |
|---|---|
| Grado F, T o M | CRÍTICO |
| Vulnerabilidad crítica detectada (Heartbleed, POODLE, FREAK, etc.) | CRÍTICO |
| Protocolo obsoleto habilitado (TLS 1.0/1.1, SSL 2.0/3.0) | ALTO |
| Grado D o E | ALTO |
| Certificado vence en < 30 días | ALTO (< 7 días: CRÍTICO) |
| Sin Forward Secrecy | MEDIO |
| Grado B o C | MEDIO |
| Sin HSTS | BAJO |
| Grado A/A+ sin otras alertas | INFORMATIVO - sin hallazgo |

Clasificación: todo hallazgo de este script es **Verificado** (evidencia directa de la API, no inferencia). Adjuntar el JSON crudo (`--json`) como evidencia cuando el hallazgo se incorpore a un informe formal.

---

## Troubleshooting

**`ERROR 441: correo no registrado`** - Falta ejecutar `--register` o el archivo `ssllabs_config.json` se perdió/no sincronizó entre equipos. Volver a registrar (idempotente, no genera duplicados en el lado de Qualys si el correo es el mismo).

**`ERROR: 'host' no pertenece a los dominios restringidos`** - El host es externo al alcance configurado con `--restrict-to`. Confirmar con el usuario la razón (ej. auditoría a proveedor) antes de reintentar con `--allow-any-domain`.

**Queda colgado en estado `DNS` o `IN_PROGRESS` por varios minutos** - Normal en la primera evaluación de un host (mínimo ~60s, a veces varios minutos si el host tiene múltiples IPs/endpoints). No cancelar ni relanzar en paralelo: eso agota el cupo de `X-Max-Assessments` del cliente.

**429 / 503 / 529 repetidos** - El script hace backoff exponencial automático hasta 5 reintentos. Si persiste tras eso, esperar ~15-30 minutos antes de reintentar manualmente (política de Qualys, no es un bug del script).

**Certificado con mismatch de nombre (grado M)** - Verificar que el `--host` usado corresponde exactamente al SAN/CN del certificado desplegado (ej. evaluar `www.ejemplo.com` cuando el cert solo cubre `ejemplo.com`, o viceversa).

**Se requiere evaluar un servidor on-prem sin exposición pública** - Esta skill no aplica; usar `openssl s_client -connect host:puerto` localmente o delegar en la skill `auditar` con acceso directo a la configuración del servidor.
