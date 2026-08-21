# Plan de implementación — Lo que queda pendiente

> Fecha de corte: **2026-08-03** · Rama: `plan-completo`
> Complementa el plan maestro (`plan_implementacion_idata_sentinel.md`, §10 Roadmap).
> Este documento **no** re-describe lo ya construido: parte del estado real del
> código y lista solo lo que falta, priorizado y con decisiones abiertas.

---

## 1. Estado actual (qué ya está listo)

Cerrado y con tests (626 pasando, 91% cobertura global):

| Fase | Alcance | Estado |
|------|---------|--------|
| 0 | Autorización, `http_client`, `rate_limiter`, `check_base` | ✅ |
| 1 | Módulo 1 Vulnerabilidades (headers, TLS, cookies, fingerprint, security files, exposición…) + `risk_engine` + CLI | ✅ |
| 2 | Reporte HTML+Jinja2 → WeasyPrint con branding IDATA | ✅ |
| 3 | Módulo 2 Inventario de activos (CT logs, DNS, tech por activo, caché de subdominios, mapa de superficie) | ✅ |
| 4 | Módulo 3 Datos Personales (señales Ley 21.719, checklist, semáforo) | ✅ |
| 5 | Módulo 4 Monitoreo continuo (baseline, diff vs. escaneo anterior, tendencia, scheduler, alertas webhook + **digest por correo**, `monitor overview`) | ✅ |
| 6 | App web FastAPI (`/acceso`, dashboard, escaneo async, vistas de monitoreo, API JSON) | ✅ *(ver brechas §2.3)* |
| — | **Modo activo** (gate + interstitial + sesión + checks activos no destructivos) | ✅ |
| 8 (parcial) | Cifrado en reposo (`crypto.py`), retención (`retention.py`), Dockerfile + `railway.json` (deploy single-service) | ✅ |

**Despliegue hoy:** un solo servicio en Railway (`serve --con-monitoreo`), SQLite
sobre volumen persistente, monitoreo corriendo dentro del proceso web, auth por
**token único compartido**.

---

## 2. Lo pendiente

### Bloque A — Fase 7: Persistencia y despliegue productivo *(el gap principal)*

El límite de fondo es **SQLite + un solo servicio**. Todo lo demás en este bloque
cae por ese hilo. `db.py` ya se diseñó con esquema plano (JSON en columnas) justo
para migrar sin reescribir consultas complejas.

- **A1 · Capa de almacenamiento con backend intercambiable.**
  Extraer una interfaz (`ScanStore` como contrato) y dejar dos adaptadores:
  SQLite (actual, para dev/local) y Postgres. Selección por variable de entorno
  (`IDATA_SENTINEL_DB` → connection string). *Sin esto, cada punto siguiente
  queda bloqueado.*
- **A2 · Adaptador Postgres (Supabase).** Traducir el DDL y las consultas
  (parámetros `?` → `%s`/`$1`, `AUTOINCREMENT` → `SERIAL/IDENTITY`, upsert
  `ON CONFLICT` ya es compatible). Migrar el mecanismo de migraciones
  (`_MIGRATIONS`) al equivalente en Postgres.
- **A3 · Script de migración de datos** SQLite → Postgres (para no perder líneas
  base ni históricos de clientes ya monitoreados).
- **A4 · Separar `web` y `worker`** en dos servicios Railway sobre la misma
  imagen (ya previsto en el Dockerfile: `serve` vs. `monitor run --forever`).
  Solo es posible una vez que ambos comparten Postgres en lugar del volumen
  SQLite de un único servicio.
- **A5 · PDFs en Supabase Storage** en vez de disco local del contenedor (hoy no
  persisten de forma confiable en redeploy). Incluye subir en la webapp y
  entregar URL firmada de descarga.
- **A6 · Supabase Auth multi-usuario** reemplazando el token único de `/acceso`.
  Permite cuentas por analista de IDATA y, más adelante, acceso de clientes.

### Bloque B — Multi-tenant (opcional, no bloqueante)

- **B1 · RLS de Supabase** para aislar datos por cliente si se ofrece acceso
  directo a clientes al dashboard. Depende de A6. Marcado en el plan maestro
  (§11.3) como *"a considerar, no bloqueante para el MVP"*.

### Bloque C — Cierre de la webapp (Fase 6, brechas menores)

- **C1 · Descarga de PDF desde la webapp.** La CLI genera PDF (`--pdf`); la
  webapp muestra resultados en HTML pero **no expone endpoint de descarga PDF**
  (roadmap §16 lo pedía). Rápido; independiente de la migración salvo por dónde
  se guarda (ver A5).
- **C2 · Alta/gestión de monitores desde la webapp.** Hoy `monitor add/overview`
  vive solo en CLI. Exponerlo en el dashboard cierra el ciclo de autoservicio.

### Bloque D — Pulido y venta (Fase 8)

- **D1 · Configuración por cliente/prospecto** (branding, módulos por defecto,
  umbrales) más allá de lo global actual.
- **D2 · Documentación de uso y de venta** (guion comercial, cómo leer el
  informe, catálogo de servicios IDATA vinculados).
- **D3 · Revisión final de manejo de errores** en escenarios límite (dominios
  caídos, certs inválidos, redirecciones infinitas) — ya bastante cubierto;
  falta pasada de auditoría explícita.

---

## 3. Orden recomendado y esfuerzo relativo

```
A1 → A2 → A3 → A4      (núcleo Fase 7: Postgres + dos servicios)   ██████ grande
        A5, A6         (storage + auth Supabase)                    ████ medio
C1, C2                 (webapp: PDF + monitores)                    ██ chico
D1–D3                  (pulido/venta)                               ██ chico
B1                     (RLS multi-tenant)                           ███ medio · opcional
```

**Camino crítico:** A1 habilita todo lo demás. C1/C2 y D1–D3 pueden hacerse en
paralelo o incluso antes que la migración si la prioridad es cerrar el producto
sobre SQLite y dejar Postgres para cuando haya volumen real de clientes.

---

## 4. Decisiones abiertas (requieren tu input)

1. **¿Migrar a Postgres ahora, o exprimir SQLite hasta tener N clientes?**
   SQLite sobre volumen persistente aguanta el MVP; Postgres se justifica cuando
   quieras dos servicios, multi-usuario o acceso de clientes. → define si el
   Bloque A es *ahora* o *después de C/D*.
2. **¿Acceso de clientes al dashboard?** Si sí, A6 + B1 pasan a ser necesarios;
   si el dashboard es solo interno de IDATA, el token único actual podría bastar
   un tiempo más y B1 se descarta.
3. **¿Supabase Storage para PDF, o basta adjuntarlo por correo / entregarlo
   manual?** Define si A5 es prioritario o cosmético.

---

## 5. Nota de alcance (no cambia)

Todo lo pendiente respeta los invariantes del proyecto: **pasivo por defecto**,
activo solo bajo autorización explícita, sin capacidades ofensivas, datos de
cliente cifrados en reposo con retención. Ningún punto de este plan introduce
fuzzing, explotación ni credential-testing.

---

*Fin. Este plan cubre exclusivamente lo pendiente al 2026-08-03; el detalle de lo
ya construido está en `plan_implementacion_idata_sentinel.md`.*
