# Plan de Implementación — Plataforma de Diagnóstico de Seguridad "IDATA Sentinel"

> **Documento maestro de especificación.** Entregar a Claude (o al equipo dev) como brief.
> Construcción por fases. No implementar todo de una vez.
>
> **Empresa:** IDATA Chile — consultora de ciberseguridad
> **Propósito:** Automatizar y estandarizar la línea de **Diagnóstico**, generando entregables ejecutivos con marca IDATA, tanto para clientes con contrato como para prospección con información pública.

---

## 0. Visión general

Plataforma modular que evalúa la postura de seguridad de un sitio/app web y produce un **reporte ejecutivo con branding IDATA**. Se integra con el catálogo de servicios existente y cubre cuatro líneas prioritarias:

1. **Identificación de vulnerabilidades**
2. **Inventario de activos tecnológicos**
3. **Datos Personales (cumplimiento Ley 21.719)**
4. **Monitoreo continuo**

Opera en **dos modos**:

| Modo | Alcance | Autorización | Uso comercial |
|------|---------|--------------|---------------|
| **Prospección (pasivo)** | Solo información pública que el servidor publica. Sin payloads, sin fuzzing, sin explotación. | No requerida | Generar leads: "detectamos X en su sitio, conversemos" |
| **Auditoría (activo no destructivo)** | Chequeos de configuración más profundos sobre activos de clientes. | **Obligatoria y registrada** | Entregable del servicio contratado |

---

## 1. Marco legal y de autorización (IMPLEMENTAR PRIMERO — Fase 0)

Base de confianza del negocio. En Chile aplica la **Ley 21.459 (delitos informáticos)**: escaneo activo sin autorización es delito. El modo pasivo es legal porque solo lee información publicada.

### 1.1 Gate de autorización (modo Auditoría)
- Exigir antes de cualquier check activo:
  - Dominio(s) y subdominios en alcance (allowlist explícita).
  - Confirmación `--i-have-authorization` / checkbox en UI.
  - Nombre del responsable que autoriza, cargo, fecha, N° de contrato/orden.
- Registrar en `audit_log.json` (append-only) con timestamp e IP de origen. Evidencia de debida diligencia.
- **Scope enforcement:** rechazar cualquier objetivo fuera de la allowlist autorizada.

### 1.2 Restricciones del modo pasivo
- Rate limit estricto (≥ 2 s entre requests, configurable).
- User-Agent honesto e identificable: `IDATA-Sentinel/1.0 (+https://idatachile.com)`.
- Respetar `robots.txt`.
- **Prohibido en cualquier modo:** fuerza bruta, prueba de credenciales, explotación de CVEs, inyecciones, DoS, fuzzing agresivo de rutas.
- Timeout global y tope de requests por dominio.

### 1.3 Disclaimer en reportes
Pie legal en cada PDF: basado en información pública / autorizado por el cliente; no constituye garantía absoluta; foto del momento del escaneo; recomendaciones sujetas a validación.

### 1.4 Manejo de datos del escaneo
- Los reportes pueden contener info sensible del cliente → cifrado en reposo y borrado programado según política de retención.

---

## 2. Arquitectura

```
idata_sentinel/
├── core/
│   ├── engine.py             # orquestador de módulos y checks
│   ├── check_base.py         # contrato estándar de un check
│   ├── authorization.py      # gate legal + scope + logging
│   ├── rate_limiter.py
│   └── http_client.py        # httpx async configurado (timeouts, UA, retries)
├── modules/
│   ├── vuln_identification/  # Línea 1
│   ├── asset_inventory/      # Línea 2
│   ├── data_privacy/         # Línea 3 (Ley 21.719)
│   └── monitoring/           # Línea 4
├── checks/                   # verificaciones atómicas reutilizables
│   ├── http_headers.py
│   ├── tls_ssl.py
│   ├── tech_fingerprint.py
│   ├── security_files.py
│   ├── cookies.py
│   ├── dns_email.py
│   ├── exposure.py
│   └── privacy_signals.py
├── scoring/
│   ├── risk_engine.py        # impacto × probabilidad → prioriza
│   └── weights.yaml
├── reporting/
│   ├── report_builder.py
│   ├── pdf_export.py         # WeasyPrint
│   └── templates/            # HTML + branding IDATA
├── storage/
│   ├── db.py                 # baseline, histórico, resultados
│   └── retention.py
├── interfaces/
│   ├── cli.py
│   └── webapp.py             # FastAPI
├── config.yaml
└── branding/                 # logo, paleta, tipografía IDATA
```

**Stack:** Python 3.11+
- HTTP async: `httpx`
- TLS: `ssl` + `cryptography`
- DNS: `dnspython`
- Fingerprint: `python-Wappalyzer` o lógica propia
- Subdominios (pasivo): CT logs vía `crt.sh`, DNS público
- PDF: `weasyprint` (HTML→PDF, ideal para branding)
- Web: `FastAPI` + `Jinja2`
- CLI: `typer`
- Cola/scheduler (monitoreo): `APScheduler` o `Celery`
- DB: `SQLite` (MVP local) → `PostgreSQL` vía **Supabase** (producción)
- Hosting: **Railway** (contenedor persistente — ver §12)

### Contrato estándar de un check
```python
{
  "id": "hsts_missing",
  "module": "vuln_identification",
  "category": "HTTP Headers",
  "severity": "medium",       # info|low|medium|high|critical
  "likelihood": "high",       # para el motor de riesgo
  "status": "fail",           # pass|fail|warning|info
  "title": "Falta cabecera HSTS",
  "finding": "El servidor no envía Strict-Transport-Security.",
  "business_impact": "Riesgo de degradación a HTTP y robo de sesión...",
  "recommendation": "Configurar HSTS max-age >= 31536000; includeSubDomains.",
  "evidence": "Response headers observados...",
  "references": ["OWASP HSTS", "CWE-319"]
}
```

---

## 3. Módulo 1 — Identificación de vulnerabilidades

> Corazón técnico. Alineado a "Análisis técnico para detectar brechas antes que los atacantes".
>
> **Plan de implementación detallado (estructura de archivos, lógica de detección por check, testing, sub-fases, Definition of Done):** ver [plan_implementacion_escaneo_vulnerabilidades.md](plan_implementacion_escaneo_vulnerabilidades.md).

### Checks pasivos (ambos modos)
- **HTTP Security Headers:** HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; detectar headers que filtran versiones (`Server`, `X-Powered-By`).
- **TLS/SSL:** versión de protocolo (marcar TLS 1.0/1.1), cipher suites débiles, validez y vencimiento del cert (alerta < 30 días), cadena de confianza, redirección forzada HTTP→HTTPS.
- **Cookies:** flags `Secure`, `HttpOnly`, `SameSite`.
- **Fingerprint + CVEs informativas:** detectar CMS/framework/servidor y versión expuesta; cruzar con CVEs conocidas **solo de forma informativa** (nunca explotar).
- **Archivos de seguridad:** `security.txt` (RFC 9116), `robots.txt` (rutas sensibles filtradas), listado de directorios abierto (solo detección).
- **Exposición de información:** errores verbosos, metadatos, formularios sin HTTPS.

### Checks adicionales de Auditoría (solo con autorización, no destructivos)
- Validación más profunda de configuración de cabeceras por ruta.
- Revisión de endpoints conocidos del cliente (provistos por él).
- Comparación contra baseline de hardening acordado.

---

## 4. Módulo 2 — Inventario de activos tecnológicos

> Alineado a "Levantamiento completo... para conocer la superficie de ataque real".

### Descubrimiento pasivo
- **Subdominios** vía Certificate Transparency logs (`crt.sh`) y DNS público.
- **Registros DNS:** A, AAAA, MX, TXT, NS, CAA.
- **Tecnologías** por dominio/subdominio (stack, CDN, WAF detectable, proveedores cloud).
- **Servicios web expuestos** (solo los publicados; sin escaneo de puertos masivo).
- **Correlación:** mapa de superficie de ataque → activos + tecnología + riesgo asociado.

### En modo Auditoría (autorizado)
- El cliente puede aportar rangos/activos internos para inventario ampliado.
- Salida: tabla de activos con owner, tecnología, exposición y hallazgos vinculados.

**Entregable:** mapa visual de superficie de ataque + tabla de activos priorizada.

---

## 5. Módulo 3 — Datos Personales (Ley 21.719)

> Diferenciador comercial fuerte en Chile: la nueva Ley 21.719 de Protección de Datos Personales crea la Agencia de Protección de Datos y multas relevantes. Muchas empresas necesitan diagnóstico de cumplimiento.

> **Nota importante:** verificar el texto y estado vigente de la Ley 21.719 y sus plazos antes de finalizar los criterios de evaluación, ya que la normativa y su reglamento pueden haberse actualizado. Este módulo evalúa **señales técnicas observables**, no reemplaza una asesoría legal.

### Señales técnicas evaluables (pasivo)
- **HTTPS obligatorio** en formularios que capturan datos personales.
- **Cookies y trackers:** inventario de cookies, banner de consentimiento presente/ausente, cookies de terceros.
- **Política de privacidad:** existencia y accesibilidad de la página; presencia de link en formularios de captura.
- **Formularios de captura:** detectar campos que recogen datos personales (RUT, email, teléfono, dirección) y si viajan cifrados.
- **Exposición accidental:** documentos/archivos con datos personales indexables públicamente.
- **Transferencias a terceros:** scripts/pixeles de terceros que reciben datos (Google, Meta, etc.).

### Checklist de cumplimiento (marco IDATA)
- Mapear hallazgos técnicos a principios de la ley: licitud, finalidad, proporcionalidad, seguridad, información al titular.
- Semáforo de cumplimiento con brechas priorizadas.
- **Recomendaciones técnicas**, con nota de que la evaluación legal formal la realiza IDATA en su servicio de "Datos Personales".

**Entregable:** informe de brechas de privacidad + checklist Ley 21.719 + recomendaciones.

---

## 6. Módulo 4 — Monitoreo continuo

> Alineado a la línea "Monitoreo". Convierte un diagnóstico puntual en servicio recurrente (ingreso mensual).

### Funcionalidad
- **Baseline:** guardar el primer escaneo como línea base por cliente/activo.
- **Re-escaneos programados:** diarios/semanales/mensuales vía scheduler.
- **Diff / detección de cambios:** nuevo subdominio, cert por vencer, header que desapareció, tecnología nueva, cookie sin flag, etc.
- **Alertas:** notificar (email/webhook) cuando cambia el riesgo o aparece un hallazgo crítico.
- **Tendencia:** evolución del score en el tiempo (gráfico para el cliente).
- **Vencimiento de certificados:** alerta proactiva (gran gancho de servicio).

### Consideraciones
- Respetar rate limits también en monitoreo.
- Panel con estado por cliente (semáforo global).
- Reportes periódicos automáticos con branding IDATA.

---

## 7. Motor de riesgo y scoring

- Cada hallazgo aporta peso según **severidad × probabilidad** (coincide con tu descripción: "priorizando por impacto y probabilidad").
- Score global 0–100 + letra A–F.
- Subscore por módulo y por categoría.
- Pesos configurables en `weights.yaml`.

| Severidad | Peso base |
|-----------|-----------|
| Critical  | 25 |
| High      | 15 |
| Medium    | 8  |
| Low       | 3  |
| Info      | 0  |

Ajuste por probabilidad (multiplicador): high ×1.0, medium ×0.7, low ×0.4.

---

## 8. Reporte ejecutivo (con branding IDATA)

Entregable que sirve **para vender y para el servicio**. Diseño limpio, orientado a decisión de negocio.

**Estructura:**
1. **Portada** — logo IDATA, cliente, dominio, fecha, modo, N° de informe.
2. **Resumen ejecutivo (1 pág.)** — score, letra, 3–5 hallazgos clave en lenguaje de negocio (riesgo reputacional, legal/21.719, operacional). Sin jerga.
3. **Semáforo por línea** — Vulnerabilidades / Activos / Datos Personales / Monitoreo.
4. **Hallazgos priorizados** — qué es, por qué importa al negocio, recomendación, esfuerzo estimado.
5. **Mapa de superficie de ataque** (Módulo 2).
6. **Cumplimiento Ley 21.719** (Módulo 3) — checklist + brechas.
7. **Anexo técnico** — detalle completo para el equipo IT del cliente.
8. **Propuesta / próximos pasos** — CTA a servicios IDATA (Controles, Gobierno, Monitoreo continuo).
9. **Disclaimer legal** (§1.3).

**Diseño:** plantilla HTML+Jinja2 → WeasyPrint. Branding (logo, paleta oscura tipo web IDATA, tipografía) parametrizado en `branding/` y `config.yaml`.

---

## 9. Interfaces

### 9.1 CLI
```bash
# Prospección pasiva
idata-sentinel scan https://prospecto.cl --mode passive --modules vuln,assets,privacy --pdf salida.pdf

# Auditoría de cliente (autorizada)
idata-sentinel scan https://cliente.cl --mode audit \
    --i-have-authorization --authorized-by "Nombre, Cargo" --contract "OC-1234" \
    --modules all --pdf salida.pdf

# Monitoreo
idata-sentinel monitor add https://cliente.cl --schedule weekly
idata-sentinel monitor status
```
- Salida en consola con resumen coloreado + PDF. Flag `--json` para integración.

### 9.2 App web (FastAPI)
- Formulario: URL, modo, módulos, (si audit) campos de autorización.
- Cola async (escaneos tardan).
- Vista de resultados + descarga PDF.
- Dashboard de monitoreo por cliente.
- **Login obligatorio** si se despliega público — no exponer un escáner abierto a terceros. Vía **Supabase Auth** (ver §12), sin construir autenticación propia.
- Multi-tenant si se ofrecerá acceso a clientes (Postgres/RLS de Supabase lo facilita).

### 9.3 Salida JSON
- Contrato estable para integrar con CRM / dashboards / otras herramientas IDATA.

---

## 10. Roadmap de construcción (orden para Claude)

**Fase 0 — Fundaciones legales y de core**
1. `authorization.py` (gate + scope + logging).
2. `http_client.py` + `rate_limiter.py`.
3. `check_base.py` (contrato estándar).

**Fase 1 — Módulo 1 (Vulnerabilidades) + MVP CLI**
4. Checks pasivos: headers, TLS, cookies, security files, fingerprint.
5. `risk_engine.py` básico.
6. CLI mínima con salida consola + JSON.

**Fase 2 — Reporte con branding IDATA**
7. Plantilla HTML + WeasyPrint.
8. Resumen ejecutivo + anexo técnico + disclaimer.

**Fase 3 — Módulo 2 (Inventario de activos)**
9. Descubrimiento de subdominios (CT logs), DNS, tech por activo.
10. Mapa de superficie de ataque en el reporte.

**Fase 4 — Módulo 3 (Datos Personales / Ley 21.719)**
11. Señales de privacidad (cookies, consentimiento, política, formularios).
12. Checklist de cumplimiento + verificar texto vigente de la ley.

**Fase 5 — Módulo 4 (Monitoreo continuo)**
13. Storage + baseline + scheduler.
14. Diff, alertas, tendencia de score.

**Fase 6 — App web**
15. FastAPI + formulario + cola async.
16. Login (Supabase Auth) + dashboard de monitoreo.
17. Descarga PDF (Supabase Storage).

**Fase 7 — Infraestructura y despliegue**
18. Provisionar proyecto Supabase (Postgres + Auth + Storage) y migrar de SQLite.
19. Dockerfile (`web` + `worker`) y dos servicios en Railway — ver §12.
20. Variables de entorno/secretos en Railway; primer deploy.

**Fase 8 — Pulido**
21. Config por cliente/prospecto, retención de datos, cifrado en reposo.
22. Tests + manejo robusto de errores (timeouts, dominios caídos, certs inválidos).
23. Documentación de uso y de venta.

---

## 11. Infraestructura y despliegue (decidido: Railway + Supabase)

### 11.1 Por qué no serverless
El motor de escaneo no encaja en un modelo request/response serverless (tipo Vercel):
- Rate limiting deliberado (≥2 s entre requests, §1.2) + múltiples checks por escaneo alargan la ejecución más allá de lo cómodo para una función serverless.
- El monitoreo continuo (§6) necesita un **proceso persistente** (`APScheduler`/`Celery`) disparando re-escaneos programados — no solo un cron puntual.
- `WeasyPrint` requiere librerías nativas del sistema (Pango, Cairo, GDK-Pixbuf) que un runtime serverless no deja instalar con control total.

**Railway** resuelve esto: contenedores persistentes desde Dockerfile, sin límite de duración de request, con soporte nativo para múltiples servicios de larga duración.

### 11.2 Servicios en Railway
Mismo repo/imagen, distinto *start command* por servicio:
- **`web`** — FastAPI (interfaz web §9.2, endpoints que disparan escaneos, salida JSON §9.3).
- **`worker`** — proceso `APScheduler`/`Celery`: monitoreo continuo (§6) y generación de reportes en background, para no bloquear requests HTTP con escaneos largos.

### 11.3 Base de datos, auth y storage: Supabase
- **Postgres** gestionado — es el destino de "`SQLite` (MVP local) → `PostgreSQL`" de §2. Railway se conecta vía connection string; no se usa el Postgres propio de Railway.
- **Auth** — cubre el "Login obligatorio" de §9.2 sin construir autenticación propia.
- **Storage** — para los PDFs generados, en vez de disco local (no persiste de forma confiable en un contenedor redeployable).
- **RLS** — a considerar si se habilita acceso multi-tenant a clientes (§9.2) más adelante; no bloqueante para el MVP.

### 11.4 Dockerfile
Imagen Python 3.11 con las dependencias nativas de WeasyPrint (`libpango-1.0-0`, `libpangocairo-1.0-0`, `libgdk-pixbuf2.0-0`, `libffi-dev`, `shared-mime-info`) vía `apt-get`, más las dependencias del proyecto vía `pip`. Un solo Dockerfile sirve para `web` y `worker`; cada servicio de Railway define su propio `CMD`/start command sobre la misma imagen.

### 11.5 Configuración y secretos
- Variables de entorno de Railway: connection string de Supabase, credenciales de Auth, claves de Storage.
- `config.yaml` y `branding/` (§2, §8) siguen versionados en el repo — son configuración pública, no secretos.
- **Nunca** commitear credenciales de Supabase; separar config pública de secretos desde el día uno.

### 11.6 CI/CD
Railway despliega automáticamente en push a la rama principal (build desde Dockerfile). Cuando exista pipeline de CI propio (tests, ver Fase 8 del roadmap §10), este debe correr **antes** del deploy — Railway solo hace build+deploy, no reemplaza el gate de tests.

---

## 12. Consideraciones finales para el desarrollador

- **Pasivo por defecto.** El activo solo se habilita tras el gate de autorización con scope.
- **Sin capacidades ofensivas.** El valor está en el diagnóstico limpio y el reporte, no en atacar.
- **Manejo de errores robusto:** dominios caídos, timeouts, redirecciones infinitas, certificados inválidos — reportar, no crashear.
- **Async** para escanear varios activos/subdominios en paralelo (respetando rate limit).
- **Ley 21.719:** verificar el texto y plazos vigentes antes de cerrar los criterios del Módulo 3; incluir disclaimer de que no sustituye asesoría legal.
- **Datos sensibles del cliente:** cifrado en reposo + política de retención.
- **Probar siempre contra activos propios de IDATA primero.**
- **Branding parametrizado** para que cada reporte salga con identidad IDATA sin tocar código.

---

*Fin del plan maestro. Construcción por fases; empezar por Fase 0.*
