# Claude Code Security Skills

Colección de [Skills de Claude Code](https://docs.claude.com/en/docs/claude-code/skills)
que integran herramientas y APIs de seguridad puntuales (escaneo TLS/SSL,
reputación de indicadores, etc.). Separada de la colección de skills de
propósito general ([`claude-code-skills-toolkit`](https://github.com/matias00allende/claude-code-skills-toolkit))
porque cada una de estas depende de un servicio externo específico, tiene su
propio modelo de cuota/autenticación, y tiene sentido evaluarla y actualizarla
de forma independiente.

## Catálogo

| Skill | Servicio externo | Qué hace |
|---|---|---|
| [`ssllabs`](ssllabs/) | [SSL Labs API v4](https://github.com/ssllabs/ssllabs-scan) (Qualys) | Verifica el despliegue TLS/SSL de un dominio público: grado (A+ a F), protocolos obsoletos, vulnerabilidades conocidas (Heartbleed, POODLE, FREAK, ROBOT), Forward Secrecy, HSTS y vencimiento de certificado. |

## Roadmap - candidatas a sumar

Esta colección está pensada para crecer con otras integraciones de seguridad
del mismo perfil (consulta a una API externa, traduce el resultado a un
hallazgo con severidad, compatible con un flujo de auditoría). Candidatas
razonables para un futuro aporte (no implementadas aún en este repo):

- **VirusTotal** - reputación de hashes, URLs, dominios e IPs.
- **URLScan.io** - análisis de URLs sospechosas (screenshot, comportamiento, indicadores).
- **Shodan** - exposición de servicios/puertos de un host o rango público.
- **HaveIBeenPwned** - verificación de dominios/correos en brechas conocidas.

Si implementas alguna, el patrón a seguir es el mismo que usa `ssllabs`: un
`SKILL.md` con triggers explícitos en su `description`, un script wrapper en
`scripts/` que resuelve la llamada a la API externa (manejo de rate-limit,
paginación y reintentos incluido), y una tabla de mapeo señal-de-la-API →
severidad de hallazgo, para que el resultado sea directamente utilizable en
un informe de auditoría.

## Instalación

Cada skill es independiente. Copia la carpeta completa a tu directorio de
skills de Claude Code:

```bash
# Windows
cp -r ssllabs/ "$USERPROFILE/.claude/skills/ssllabs/"

# macOS / Linux
cp -r ssllabs/ "$HOME/.claude/skills/ssllabs/"
```

## Licencia

MIT. Ver [LICENSE](LICENSE).
