# Guía del servicio de Diagnóstico de Seguridad

**IDATA Chile** · Documento de bienvenida para clientes

---

<!-- interno:inicio -->
> **Cómo usar esta guía (nota interna para IDATA)**
>
> Este bloque **no aparece en el PDF** que se entrega al cliente: el renderizador
> lo elimina automáticamente. Para conservarlo, use `--con-notas-internas`.
>
> Todo lo que aparece entre [[dobles corchetes]] debe completarse antes de
> entregar el documento: nombres, plazos, montos y datos de contacto. No se
> incluyen plazos ni precios por defecto para no comprometer condiciones
> comerciales que no estén en el contrato.
>
> El Anexo A es el formulario de autorización y es **bloqueante**: sin él firmado
> no puede ejecutarse ningún escaneo en modo auditoría.
>
> Generar el PDF:
> `idata-sentinel doc docs/guia_cliente.md --pdf guia-cliente.pdf`

---
<!-- interno:fin -->


## Índice

1. [Qué es este servicio](#1-qué-es-este-servicio)
2. [Qué recibirá](#2-qué-recibirá)
3. [El proceso, paso a paso](#3-el-proceso-paso-a-paso)
   - [Paso 1 — Reunión de inicio](#paso-1--reunión-de-inicio)
   - [Paso 2 — Definición del alcance](#paso-2--definición-del-alcance)
   - [Paso 3 — Autorización formal](#paso-3--autorización-formal)
   - [Paso 4 — Preparación de su lado](#paso-4--preparación-de-su-lado)
   - [Paso 5 — Ejecución del diagnóstico](#paso-5--ejecución-del-diagnóstico)
   - [Paso 6 — Entrega y presentación del reporte](#paso-6--entrega-y-presentación-del-reporte)
   - [Paso 7 — Cómo leer el reporte](#paso-7--cómo-leer-el-reporte)
   - [Paso 8 — Plan de remediación](#paso-8--plan-de-remediación)
   - [Paso 9 — Re-escaneo de verificación](#paso-9--re-escaneo-de-verificación)
   - [Paso 10 — Monitoreo continuo](#paso-10--monitoreo-continuo)
4. [Lo que este servicio no hace](#4-lo-que-este-servicio-no-hace)
5. [Manejo de su información](#5-manejo-de-su-información)
6. [Preguntas frecuentes](#6-preguntas-frecuentes)

**Anexos**

- [Anexo A — Formulario de autorización](#anexo-a--formulario-de-autorización)
- [Anexo B — Checklist de preparación](#anexo-b--checklist-de-preparación)
- [Anexo C — Glosario](#anexo-c--glosario)
- [Anexo D — Qué verá en sus registros](#anexo-d--qué-verá-en-sus-registros)
- [Anexo E — Responsables del encargo](#anexo-e--responsables-del-encargo)

---

## 1. Qué es este servicio

El **Diagnóstico de Seguridad** evalúa la postura de seguridad de su presencia
web y le entrega un informe con los hallazgos priorizados por impacto de negocio
y por probabilidad de que se materialicen.

El diagnóstico se realiza con **IDATA Sentinel**, nuestra plataforma propia de
análisis. Es un servicio de **observación y análisis**, no de intrusión: en
ningún momento se intenta explotar una vulnerabilidad, adivinar una contraseña
ni provocar una interrupción del servicio.

### Las cuatro líneas del diagnóstico

Según lo contratado, el diagnóstico cubre una o varias de estas líneas:

| Línea | Qué responde | ¿Contratada? |
|---|---|---|
| **Identificación de vulnerabilidades** | ¿Cómo está configurado el sitio y qué revela sin querer? | ☐ |
| **Inventario de activos tecnológicos** | ¿Cuál es la superficie de ataque real, más allá de la declarada? | ☐ |
| **Datos Personales (Ley 21.719)** | ¿Qué señales técnicas de cumplimiento se observan? | ☐ |
| **Monitoreo continuo** | ¿Qué cambió desde la última revisión? | ☐ |

### Los dos modos de ejecución

| Modo | Alcance | Requisito |
|---|---|---|
| **Prospección (pasivo)** | Solo información que sus servidores ya publican a cualquier visitante de Internet. | Ninguno adicional |
| **Auditoría (activo no destructivo)** | Añade las rutas, endpoints y activos que **usted declara**, y compara contra su línea base de hardening. | Autorización firmada (Anexo A) |

El modo auditoría **no habilita técnicas nuevas ni más agresivas**. Habilita
únicamente que revisemos superficie adicional que usted nos indica. Las
prohibiciones de la sección 4 rigen igual en ambos modos.

### Por qué la autorización es obligatoria

En Chile rige la **Ley 21.459 sobre delitos informáticos**. Analizar activamente
un sistema ajeno sin autorización del titular constituye delito. Por eso:

- El **modo pasivo** es legal sin autorización, porque solo leemos información
  que su servidor entrega públicamente a cualquiera que la solicite.
- El **modo auditoría** exige autorización escrita, con alcance delimitado y
  responsable identificado.

Esta exigencia protege a ambas partes. No es un trámite administrativo: es la
base sobre la que se sostiene la legalidad del encargo.

---

## 2. Qué recibirá

| Entregable | Formato | Cuándo |
|---|---|---|
| Reporte ejecutivo de diagnóstico | PDF con identidad IDATA | 5 días hábiles desde el término del escaneo |
| Anexo técnico detallado | Incluido en el PDF (sección 7) | Junto al reporte |
| Resultados estructurados | JSON, para integrar con sus herramientas | A solicitud |
| Presentación de resultados | Reunión de 60 minutos | Dentro de la semana siguiente a la entrega |
| Re-escaneo de verificación | Informe comparativo | 1 incluido, dentro de 60 días |
| Alertas de monitoreo | Correo o webhook | Solo si contrató monitoreo |
| Reporte de tendencia | PDF periódico | Solo si contrató monitoreo |

### Estructura del reporte

El reporte tiene nueve secciones, en este orden:

| # | Sección | Para quién |
|---|---|---|
| 1 | Portada con score y nota global | — |
| 2 | Resumen ejecutivo | Dirección, sin lenguaje técnico |
| 3 | Semáforo por línea de servicio y tendencia | Dirección |
| 4 | Hallazgos priorizados | Dirección y TI |
| 5 | Mapa de superficie de ataque | TI |
| 6 | Cumplimiento Ley 21.719 | Dirección, Legal y TI |
| 7 | Anexo técnico | TI |
| 8 | Próximos pasos | Dirección |
| 9 | Alcance y limitaciones | Todos — **lea esta sección** |

---

## 3. El proceso, paso a paso

### Paso 1 — Reunión de inicio

**Quién participa:** por su parte, un responsable con autoridad para autorizar el
análisis (típicamente Gerente de TI, CISO o Gerente General) y, si existe, quien
opere la infraestructura. Por parte de IDATA, el responsable del encargo y, cuando el
alcance lo amerite, el analista asignado. Ambos quedan identificados en el
[Anexo E](#anexo-e--responsables-del-encargo).

**Qué se define:**

1. Qué líneas del diagnóstico se ejecutan.
2. Modo de ejecución: pasivo, auditoría, o pasivo primero y auditoría después.
3. Lista de dominios en alcance.
4. Ventana de ejecución acordada.
5. Quién es el punto de contacto técnico durante la ejecución.
6. Quién recibe el reporte y quién recibe las alertas.

**Qué debe traer preparado:**

- Lista de dominios y subdominios que su organización considera propios.
- Nombre y cargo de quien firmará la autorización.
- Número de contrato u orden de compra.

> **Nota:** no necesita traer un inventario completo ni exacto. Una de las cosas
> que el diagnóstico revela es precisamente qué activos existen que nadie tenía
> registrados. Traiga lo que tenga.

---

### Paso 2 — Definición del alcance

El alcance se expresa como una **lista blanca de dominios**. Todo lo que quede
fuera de esa lista no se analiza, y la plataforma lo rechaza automáticamente
incluso si se indicara por error.

**Cómo funciona la lista blanca**

Si declara `sucliente.cl`, quedan en alcance:

- ✅ `sucliente.cl`
- ✅ `www.sucliente.cl`, `api.sucliente.cl`, y cualquier otro subdominio
- ❌ `sucliente.com` — es otro dominio, debe declararlo aparte
- ❌ `sucliente.cdn-externo.com` — pertenece a un tercero

**Decisiones que debe tomar en este paso**

| Decisión | Por qué importa |
|---|---|
| ¿Incluye todos sus dominios o solo algunos? | Un dominio olvidado suele ser el menos protegido |
| ¿Incluye entornos de prueba (`dev`, `staging`, `qa`)? | Recomendamos que sí: son la puerta de entrada preferida por los atacantes |
| ¿Hay activos alojados en terceros (SaaS, CDN, marketplace)? | Solo podemos analizar lo que usted tiene facultad para autorizar |
| ¿Hay sistemas críticos que requieran precaución adicional? | Los coordinamos en una ventana específica |

**Si contrató modo auditoría**, además puede aportar:

| Aporte | Ejemplo | Efecto |
|---|---|---|
| Rutas específicas a revisar | `/admin`, `/intranet`, `/api/v2` | Se evalúan cabeceras y exposición en esas rutas |
| Endpoints conocidos | `/api/health`, `/status` | Se revisan igual que la raíz |
| Activos internos adicionales | `intranet.sucliente.cl` | Se agregan al inventario |
| Línea base de hardening | «Todos los sitios deben enviar HSTS con `max-age` de un año» | Se reporta cada desviación respecto de su propio estándar |

> **Importante sobre activos de terceros.** Si su sitio está alojado en un
> proveedor (Shopify, WordPress.com, un CDN), usted puede autorizar el análisis
> de **su** dominio, pero no de la infraestructura compartida del proveedor.
> Cuando detectemos que un activo pertenece a un tercero, lo informaremos y
> quedará fuera del análisis activo.

---

### Paso 3 — Autorización formal

**Este paso es bloqueante para el modo auditoría.** Sin la autorización firmada,
la plataforma no ejecuta ningún chequeo activo: degrada automáticamente a modo
pasivo y registra el motivo.

**Complete y firme el [Anexo A](#anexo-a--formulario-de-autorización).** Debe
contener, como mínimo:

1. Razón social y RUT de la organización.
2. Nombre, cargo y datos de contacto de quien autoriza.
3. Número de contrato u orden de compra.
4. Lista completa de dominios en alcance.
5. Declaración expresa de titularidad o de facultades para autorizar.
6. Firma y fecha.

**Quién debe firmar.** Una persona con facultades para comprometer a la
organización respecto de sus activos informáticos. Si tiene dudas sobre quién
corresponde en su estructura, consúltelo con su área legal antes de firmar.

**Qué hacemos con la autorización.** Cada decisión de autorización queda
registrada en un **log de solo-escritura** con fecha, hora, responsable y
número de contrato. Ese registro es la evidencia de debida diligencia del
encargo, y está disponible para usted en cualquier momento.

Se registran también las autorizaciones **rechazadas** y su motivo: alcance
incompleto, o un objetivo fuera de la lista blanca. Esa trazabilidad es
deliberada.

---

### Paso 4 — Preparación de su lado

Este paso evita falsos negativos y falsas alarmas. Dedíquele atención: un
diagnóstico que su WAF bloqueó no le sirve a nadie.

#### 4.1 Avise a su equipo de operaciones y a su SOC

Verán tráfico automatizado identificado. Si nadie está avisado, es habitual que
alguien lo bloquee a mitad del escaneo o abra un incidente innecesario.

Comparta con ellos el [Anexo D](#anexo-d--qué-verá-en-sus-registros), que
describe exactamente qué peticiones verán.

#### 4.2 Permita nuestro User-Agent en su WAF o CDN

Todas nuestras peticiones se identifican honestamente con:

```
IDATA-Sentinel/1.0 (+https://idatachile.com)
```

Si tiene Cloudflare, Imperva, Akamai, AWS WAF o similar, agregue una regla de
excepción para ese User-Agent durante la ventana acordada. Sin ella, el WAF
puede responder por su servidor y el diagnóstico reportará la configuración del
WAF en lugar de la suya.

> Si prefiere no crear excepciones, indíquenoslo: el diagnóstico se ejecuta
> igual, pero dejaremos constancia de que los resultados reflejan la respuesta
> del WAF y no necesariamente la del origen.

#### 4.3 Confirme la ventana de ejecución

El diagnóstico es liviano por diseño, pero conviene acordar la ventana:

- Esperamos **al menos 2 segundos entre peticiones al mismo servidor**, por
  política de higiene de red.
- Existe un **tope de peticiones por dominio**, para no generar carga.
- Por eso un diagnóstico completo **tarda entre varios minutos y algunas horas**,
  según cuántos activos se descubran. No es un escaneo instantáneo.

#### 4.4 Si contrató modo auditoría, entregue sus aportes

Rutas, endpoints, activos adicionales y línea base de hardening, según lo
definido en el Paso 2. Un archivo de texto o una planilla es suficiente.

#### 4.5 Complete el [Anexo B](#anexo-b--checklist-de-preparación)

Es una lista de verificación breve. Devuélvala firmada por su contacto técnico.

---

### Paso 5 — Ejecución del diagnóstico

**Qué ocurre, en orden:**

1. **Verificación de autorización y alcance.** Si algo no cuadra, el escaneo se
   detiene o degrada a pasivo antes de emitir una sola petición.
2. **Lectura de `robots.txt`.** Se respeta: en modo pasivo no solicitamos ninguna
   ruta que usted haya marcado como no rastreable.
3. **Descubrimiento de activos.** Consultamos los registros públicos de
   Certificate Transparency —el mismo registro que audita la emisión de
   certificados en todo Internet— para encontrar subdominios. Esta consulta no
   toca su infraestructura.
4. **Resolución DNS** de cada activo encontrado.
5. **Peticiones web**, en dos niveles:
   - Al **dominio principal**, el conjunto acotado de rutas canónicas que detalla
     el [Anexo D](#anexo-d--qué-verá-en-sus-registros). Son seis rutas fijas y
     conocidas, no un barrido.
   - A **cada subdominio descubierto**, una única petición, para identificar
     tecnología, estado y protecciones perimetrales.
6. **Inspección TLS** mediante una negociación estándar al puerto 443, la misma
   que hace cualquier navegador al abrir su sitio.
7. **Análisis y correlación** de todo lo observado.

**Durante la ejecución** su punto de contacto técnico recibirá aviso al inicio y
al término. Si algo se comporta de forma inesperada, detenemos el escaneo y lo
conversamos antes de continuar.

**Impacto esperado en su operación: ninguno.** El volumen de peticiones es
comparable al de un visitante navegando su sitio con calma.

---

### Paso 6 — Entrega y presentación del reporte

Recibirá el reporte en PDF y una reunión para presentarlo. Recomendamos que
asistan:

- **Dirección o gerencia**, para las secciones 2, 3, 4 y 8.
- **Responsable de TI o del proveedor de hosting**, para las secciones 5 y 7.
- **Área legal o de cumplimiento**, si contrató la línea de Datos Personales
  (sección 6).

En la reunión revisamos los hallazgos, aclaramos dudas y acordamos el plan de
remediación del Paso 8.

---

### Paso 7 — Cómo leer el reporte

#### 7.1 El score y la nota

El reporte abre con un **score de 0 a 100** y una **nota de A a F**.

| Nota | Score | Lectura |
|---|---|---|
| **A** | 90–100 | Postura sólida. Quedan mejoras de refinamiento. |
| **B** | 80–89 | Buena postura con brechas puntuales. |
| **C** | 70–79 | Brechas relevantes que conviene cerrar en plazo corto. |
| **D** | 60–69 | Varias brechas significativas acumuladas. |
| **F** | 0–59 | Requiere atención prioritaria. |

**Cómo se calcula.** Cada hallazgo descuenta puntos según su **severidad**
multiplicada por su **probabilidad**:

| Severidad | Descuento base | | Probabilidad | Multiplicador |
|---|---|---|---|---|
| Crítico | 25 | | Alta | × 1,0 |
| Alto | 15 | | Media | × 0,7 |
| Medio | 8 | | Baja | × 0,4 |
| Bajo | 3 | | | |
| Informativo | 0 | | | |

Un hallazgo **crítico pero improbable** descuenta 10 puntos; uno **medio y muy
probable**, 8. Esa es la diferencia entre "es grave en teoría" y "esto va a
pasar". El score refleja riesgo real, no cantidad de hallazgos.

**Dos cosas que no descuentan puntos:**

- Los hallazgos **informativos**, que son inventario, no problemas.
- Los hallazgos **no evaluables** —un activo que no respondió, un timeout—.
  "No pude medirlo" no es lo mismo que "está mal", y no queremos que un servidor
  caído durante el escaneo le baje artificialmente la nota.

#### 7.2 Cómo priorizar

La sección 4 del reporte ya viene ordenada por gravedad. Pero para planificar,
use estos dos criterios juntos:

| | **Fácil de corregir** | **Difícil de corregir** |
|---|---|---|
| **Alto impacto** | **Hágalo esta semana.** Suele ser una cabecera, un certificado o un registro DNS. | **Planifíquelo con recursos.** Requiere cambio de arquitectura o proveedor. |
| **Bajo impacto** | Inclúyalo en el próximo mantenimiento. | Documente la decisión de no hacerlo, y revísela más adelante. |

La mayoría de los hallazgos de configuración caen en el cuadrante superior
izquierdo: **son cambios de minutos que mueven el score de forma notoria.**

#### 7.3 Cada hallazgo tiene la misma estructura

| Campo | Qué le dice |
|---|---|
| Severidad | Qué tan grave sería si se explotara |
| Probabilidad | Qué tan factible es que ocurra |
| Título | Qué se detectó |
| Por qué importa | La consecuencia **de negocio**, no la técnica |
| Qué hacer | La acción concreta recomendada |
| Evidencia | Lo que observamos, para que su equipo lo verifique |
| Referencias | El estándar o la norma aplicable |

#### 7.4 El mapa de superficie de ataque (sección 5)

Es la tabla de todos los activos encontrados, con su tecnología, su exposición y
su riesgo asociado.

**Presté atención especial a:**

- **Activos que no reconoce.** Es el hallazgo más valioso del diagnóstico. Un
  subdominio que nadie recuerda haber creado es un subdominio que nadie está
  parchando.
- **Entornos no productivos publicados** (marcados `DEV`, `STAGING`, `TEST`).
  Suelen tener datos reales y menos protección que producción.
- **Riesgo de apropiación de subdominio** (marcado `TAKEOVER`). Significa que un
  subdominio suyo apunta a un servicio externo que ya no existe: un tercero
  podría reclamarlo y publicar contenido bajo su marca, con certificado válido.
  **Es el hallazgo que recomendamos cerrar primero**, porque el daño reputacional
  es inmediato.

#### 7.5 La sección de Ley 21.719 (sección 6)

Un semáforo por cada principio de la ley: licitud, información al titular,
finalidad y transferencias, proporcionalidad, y seguridad del tratamiento.

**Lea con atención el alcance de esta sección.** Evaluamos **señales técnicas
observables**: si hay política de privacidad accesible, si los formularios que
capturan datos personales viajan cifrados, si se activan rastreadores antes de
obtener consentimiento, a qué terceros se transfieren datos.

**Esto no es una calificación legal de cumplimiento** ni sustituye una asesoría
jurídica. Un semáforo verde no certifica que su organización cumpla la ley; un
rojo sí indica una brecha técnica verificable que conviene cerrar. Para la
evaluación jurídica formal, IDATA ofrece su servicio específico de Datos
Personales.

---

### Paso 8 — Plan de remediación

**Quién ejecuta.** Salvo que haya contratado el servicio de Controles, la
remediación la ejecuta su equipo o su proveedor de hosting. El reporte está
escrito para que puedan hacerlo sin nosotros.

**Cómo organizarlo:**

1. **Asigne un responsable por hallazgo.** Un hallazgo sin dueño no se cierra.
2. **Empiece por los cambios de configuración.** Cabeceras, certificados,
   registros DNS y flags de cookies: mucho impacto, poco esfuerzo.
3. **Trate los activos no reconocidos como decisión, no como tarea.** Por cada
   uno: ¿se sigue usando? Si no, retírelo de Internet. Si sí, ¿quién lo
   mantiene?
4. **Documente lo que decide no corregir.** Una brecha aceptada con criterio y
   registrada es una postura defendible; una brecha olvidada, no.
5. **Fije una fecha de re-escaneo** antes de empezar.

**Si necesita apoyo**, IDATA acompaña la ejecución mediante su servicio de
Controles y el diseño del marco de responsabilidades mediante Gobierno.

---

### Paso 9 — Re-escaneo de verificación

Cuando su equipo termine las correcciones, ejecutamos un nuevo escaneo y le
entregamos un **informe comparativo** que muestra:

- Qué hallazgos se resolvieron.
- Qué hallazgos siguen abiertos.
- Qué hallazgos nuevos aparecieron.
- Cuánto se movió el score.

Es el entregable que le permite mostrar avance con evidencia objetiva, en lugar
de una afirmación.

**Condiciones del re-escaneo.** El servicio incluye **un re-escaneo de verificación
sin costo adicional**, ejecutable dentro de los **60 días** siguientes a la entrega
del informe. Se coordina cuando su equipo confirme que terminó las correcciones.

Si necesita más de uno, o si el plazo se le queda corto, se cotiza por separado o se
resuelve contratando el monitoreo continuo del Paso 10, que lo cubre de forma
permanente.

---

### Paso 10 — Monitoreo continuo

> Aplica solo si contrató esta línea.

Un diagnóstico es una fotografía. El monitoreo la convierte en vigilancia.

**Cómo funciona.** El primer escaneo queda como **línea base**. Cada escaneo
posterior se compara contra ella, y lo que se le informa no es el listado
completo otra vez, sino **lo que cambió**.

**Cadencia disponible:**

| Cadencia | Recomendada para |
|---|---|
| Diaria | Activos críticos o de alta rotación de cambios |
| Semanal | La mayoría de las organizaciones |
| Mensual | Presencia web estable, con pocos despliegues |

**Cuándo recibirá una alerta:**

| Situación | Nivel |
|---|---|
| Apareció un hallazgo grave que no existía | Crítico |
| Un hallazgo existente se agravó | Advertencia |
| Apareció un activo nuevo en su superficie de ataque | Advertencia |
| Un certificado está por vencer | Advertencia |
| El score cayó 10 puntos o más | Advertencia |
| El score mejoró 10 puntos o más | Informativo |

**Deliberadamente no le enviamos una alerta por cada escaneo.** Una alerta que
llega siempre deja de leerse, y entonces no sirve para nada. Solo se notifica
cuando algo cambió.

**Qué debe definir:**

- Quién recibe las alertas (correo o webhook a su canal de operaciones).
- Cadencia por cada objetivo.
- Si hay ventanas en que prefiere no recibir escaneos.

---

## 4. Lo que este servicio no hace

Esta sección es tan importante como la anterior. Léala con su equipo técnico.

### Técnicas que nunca se emplean, en ningún modo

| No hacemos | Por qué |
|---|---|
| Fuerza bruta ni prueba de contraseñas | Podría bloquear cuentas reales de sus usuarios |
| Explotación de vulnerabilidades | Diagnosticamos, no atacamos |
| Inyecciones (SQL, XSS, comandos) | Podría alterar o destruir datos |
| Denegación de servicio o pruebas de carga | Podría interrumpir su operación |
| Fuzzing agresivo de rutas por diccionario | Genera ruido y carga innecesaria |
| Ingeniería social o phishing a su personal | Fuera del alcance de este servicio |
| Reclamar un subdominio en riesgo de apropiación | Sería tomar control de infraestructura ajena. **Le informamos el riesgo; nunca ocupamos el recurso.** |

### Sobre las vulnerabilidades conocidas (CVE)

Cuando detectamos que un producto expone su número de versión, cruzamos esa
versión con una base de vulnerabilidades publicadas y se lo informamos.

**Ese hallazgo es informativo y no verificado.** No comprobamos si su instalación
es realmente explotable: puede tener un parche aplicado que no cambia el número
de versión visible, o una mitigación en el WAF. Lo que le decimos es "esta
versión tiene vulnerabilidades publicadas, conviene revisarla", no "usted es
vulnerable".

### Limitaciones que debe conocer

1. **Un resultado sin hallazgos no significa ausencia de vulnerabilidades.**
   Significa que no encontramos ninguna por los métodos empleados. Un diagnóstico
   pasivo no reemplaza un test de intrusión.
2. **Es una fotografía del momento del escaneo.** Un despliegue al día siguiente
   puede cambiar el resultado. De ahí el valor del monitoreo continuo.
3. **Solo vemos lo observable desde Internet.** La seguridad de su red interna,
   de sus estaciones de trabajo y de sus procesos queda fuera de este servicio.
4. **No revisamos el código fuente** de sus aplicaciones.
5. **Si un WAF responde por su servidor**, evaluamos lo que el WAF expone. Por eso
   pedimos la excepción del Paso 4.2.
6. **El detrás del login queda fuera**, salvo que en modo auditoría usted nos
   entregue explícitamente rutas y credenciales de prueba, lo que debe pactarse
   por separado.

---

## 5. Manejo de su información

Los resultados del diagnóstico describen las debilidades de su organización. Si
se filtraran, un atacante recibiría el mapa ya hecho. Los tratamos en
consecuencia.

| Aspecto | Cómo lo manejamos |
|---|---|
| **Cifrado en reposo** | Los hallazgos y el inventario se almacenan cifrados |
| **Retención** | 12 meses desde el escaneo. Al cumplirse se eliminan, salvo instrucción contraria suya |
| **Acceso** | Restringido al equipo asignado a su encargo |
| **Registro de autorizaciones** | Log de solo-escritura, disponible para usted |
| **Distribución del reporte** | Solo a los destinatarios que usted designe en el Anexo E |
| **Eliminación anticipada** | Puede solicitarla por escrito en cualquier momento |

En lo que respecta a los datos personales que pudieran quedar comprendidos, el
tratamiento se rige por [[referencia a la cláusula del contrato o al acuerdo de
confidencialidad]].

---

## 6. Preguntas frecuentes

**¿El escaneo puede caer mi sitio?**
No es el objetivo ni el comportamiento esperado. Esperamos al menos 2 segundos
entre peticiones al mismo servidor y hay un tope de peticiones por dominio. La
carga es comparable a la de un visitante navegando con calma. Si su
infraestructura fuera tan frágil que este volumen la afectara, eso en sí mismo
sería un hallazgo relevante.

**¿Necesito darles credenciales de acceso?**
No para el diagnóstico estándar. Si quiere que revisemos áreas autenticadas, se
pacta por separado y con credenciales de prueba creadas para el encargo.

**¿Por qué encontraron subdominios que yo no conocía?**
Porque los certificados TLS se registran en un archivo público y auditable
(Certificate Transparency). Cada certificado emitido para uno de sus subdominios
queda ahí. Es información pública que cualquiera puede consultar, incluido un
atacante. Que usted no la conociera es exactamente el problema que el
diagnóstico resuelve.

**Un hallazgo me parece un falso positivo. ¿Qué hago?**
Indíquenoslo con el identificador del hallazgo. Cada uno incluye la evidencia
observada para que su equipo la verifique. Si es un falso positivo, corregimos
el reporte y ajustamos la regla de detección.

**¿Puedo mostrar este reporte a un cliente o a un auditor?**
Sí, es suyo. Tenga presente que contiene el detalle de sus debilidades: trátelo
con el mismo cuidado que cualquier documento sensible y considere entregar solo
el resumen ejecutivo cuando el detalle técnico no sea necesario.

**¿Cada cuánto conviene repetir el diagnóstico?**
Como mínimo, después de cada cambio significativo en su presencia web. Si no hay
un evento que lo motive, la práctica habitual es trimestral. Si contrató
monitoreo continuo, esto ocurre solo.

**¿Qué pasa si durante el escaneo detectan algo grave?**
Si encontramos un hallazgo crítico con exposición inmediata, no esperamos a la
entrega del reporte: se lo comunicamos a su contacto técnico en cuanto lo
confirmamos.

**¿La evaluación de Ley 21.719 me sirve ante la Agencia de Protección de Datos?**
Le sirve como **insumo técnico**: identifica brechas verificables y las prioriza.
No es una certificación de cumplimiento ni un informe jurídico. Para eso está el
servicio de Datos Personales de IDATA.

---

# Anexos

## Anexo A — Formulario de autorización

> **Este documento es obligatorio para el modo auditoría.** Sin él firmado, el
> diagnóstico se ejecuta únicamente en modo pasivo.

### A.1 Identificación de la organización

| Campo | Dato |
|---|---|
| Razón social | |
| RUT | |
| Dirección | |

### A.2 Persona que autoriza

| Campo | Dato |
|---|---|
| Nombre completo | |
| Cargo | |
| Correo electrónico | |
| Teléfono | |

### A.3 Referencia contractual

| Campo | Dato |
|---|---|
| N° de contrato u orden de compra | |
| Fecha de inicio del encargo | |

### A.4 Dominios en alcance

Todo dominio no listado aquí queda **excluido** del análisis. Incluya un dominio
por línea; sus subdominios quedan comprendidos automáticamente.

```
1. ____________________________________
2. ____________________________________
3. ____________________________________
4. ____________________________________
5. ____________________________________
```

### A.5 Activos adicionales aportados por el cliente *(opcional)*

Solo se aceptan si pertenecen a alguno de los dominios de A.4.

```
1. ____________________________________
2. ____________________________________
3. ____________________________________
```

### A.6 Rutas y endpoints específicos a revisar *(opcional)*

```
1. ____________________________________
2. ____________________________________
3. ____________________________________
```

### A.7 Línea base de hardening acordada *(opcional)*

Si su organización tiene un estándar propio de configuración, descríbalo o
adjúntelo. Se reportará cada desviación respecto de él.

```
______________________________________________________________
______________________________________________________________
```

### A.8 Ventana de ejecución acordada

| Campo | Dato |
|---|---|
| Desde | |
| Hasta | |
| Restricciones horarias | |

### A.9 Declaración

> Declaro que la organización identificada en A.1 es titular de los activos
> informáticos listados en A.4 y A.5, o cuenta con facultades suficientes para
> autorizar su evaluación técnica.
>
> Autorizo a **IDATA Chile** a ejecutar sobre dichos activos el Diagnóstico de
> Seguridad descrito en esta guía, en modo auditoría no destructivo y dentro de
> la ventana señalada en A.8.
>
> Declaro haber leído y comprendido la sección 4 de esta guía, «Lo que este
> servicio no hace», y en particular que el servicio **no constituye un test de
> intrusión** y que un resultado sin hallazgos no implica ausencia de
> vulnerabilidades.
>
> Esta autorización puede ser revocada por escrito en cualquier momento.

| | |
|---|---|
| Firma | |
| Nombre | |
| Cargo | |
| Fecha | |

---

## Anexo B — Checklist de preparación

Para completar por su contacto técnico antes de la ventana de ejecución.

**Alcance y autorización**

- ☐ Lista de dominios revisada y completa (Anexo A.4)
- ☐ Formulario de autorización firmado y entregado
- ☐ Decidido si se incluyen entornos no productivos
- ☐ Identificados los activos alojados en terceros

**Coordinación interna**

- ☐ Equipo de operaciones avisado de la ventana de ejecución
- ☐ SOC o proveedor de monitoreo avisado
- ☐ Anexo D compartido con quien revisa los registros
- ☐ Contacto técnico designado y disponible durante la ventana

**Configuración perimetral**

- ☐ User-Agent `IDATA-Sentinel/1.0` permitido en WAF/CDN
- ☐ Verificado que no haya bloqueo por geolocalización o por tasa
- ☐ Si no se crearán excepciones, informado a IDATA

**Solo modo auditoría**

- ☐ Rutas específicas entregadas
- ☐ Endpoints conocidos entregados
- ☐ Línea base de hardening entregada, si existe

**Entrega de resultados**

- ☐ Destinatarios del reporte definidos (Anexo E)
- ☐ Destinatarios de alertas definidos, si contrató monitoreo
- ☐ Fecha de la reunión de presentación agendada

| | |
|---|---|
| Completado por | |
| Cargo | |
| Fecha | |

---

## Anexo C — Glosario

| Término | Qué significa en este reporte |
|---|---|
| **Activo** | Cualquier host o servicio suyo alcanzable desde Internet: un dominio, un subdominio, una API |
| **Superficie de ataque** | El conjunto de todos sus activos accesibles. Cada uno es una puerta potencial |
| **Hallazgo** | Una observación concreta con severidad, impacto de negocio y recomendación |
| **Severidad** | Qué tan grave sería el hallazgo si se explotara |
| **Probabilidad** | Qué tan factible es que se explote en la práctica |
| **Score** | Puntaje de 0 a 100 que resume la postura, ponderando severidad por probabilidad |
| **Línea base** | El primer escaneo registrado. Todo escaneo posterior se compara contra él |
| **No evaluable** | Un chequeo que no pudo completarse (host caído, timeout). No es un hallazgo y no descuenta puntos |
| **Modo pasivo** | Solo se lee información que su servidor publica a cualquiera |
| **Modo auditoría** | Se añade la superficie que usted declara. No habilita técnicas más agresivas |
| **CVE** | Identificador público de una vulnerabilidad conocida en un producto |
| **HSTS** | Cabecera que obliga al navegador a usar siempre HTTPS con su sitio |
| **CSP** | Cabecera que limita qué scripts puede ejecutar su sitio. Principal defensa contra XSS |
| **CORS** | Reglas que definen qué otros sitios pueden leer datos desde su dominio |
| **SPF, DMARC** | Registros DNS que impiden que un tercero envíe correo suplantando su dominio |
| **CAA** | Registro DNS que restringe qué autoridades pueden emitir certificados para su dominio |
| **DNSSEC** | Firma criptográfica de sus registros DNS, para que no puedan ser falsificados |
| **Apropiación de subdominio** | Un subdominio suyo apunta a un servicio externo inexistente, y un tercero podría reclamarlo |
| **Certificate Transparency** | Registro público y auditable de todos los certificados TLS emitidos en Internet |
| **WAF** | Firewall de aplicación web, que filtra tráfico antes de que llegue a su servidor |
| **Session replay** | Herramienta que graba la navegación del usuario, incluido lo que escribe en formularios |

---

## Anexo D — Qué verá en sus registros

Documento para su equipo de operaciones y su SOC.

### Identificación del tráfico

Todas las peticiones llevan este User-Agent, sin excepción y sin ocultarse:

```
IDATA-Sentinel/1.0 (+https://idatachile.com)
```

### Peticiones que verá — lista completa

Esta es la lista exhaustiva. **No hay peticiones no declaradas aquí.**

| Petición | Cuándo | Propósito |
|---|---|---|
| `GET /robots.txt` | Al inicio, una vez | Leer y respetar su política de rastreo |
| `GET /` | Una vez por activo descubierto | Identificar tecnología, cabeceras y estado |
| `GET /.well-known/security.txt` | Una vez | Verificar el canal de contacto de seguridad (RFC 9116) |
| `GET /security.txt` | Una vez | Igual que el anterior, ubicación alternativa |
| `GET /.env` | Una vez | Comprobar si el archivo de configuración quedó accesible |
| `GET /.git/HEAD` | Una vez | Comprobar si el repositorio Git quedó expuesto |
| Negociación TLS al puerto 443 | Una vez por activo | Inspeccionar protocolo, cifradores y certificado |
| Consultas DNS | Varias por activo | Inventariar registros A, AAAA, CNAME, MX, TXT, NS, CAA |

> **Sobre `/.env` y `/.git/HEAD`.** Reconocerá estas dos rutas como firmas
> clásicas de ataque, y por eso las declaramos explícitamente: son las dos fugas
> de configuración más frecuentes y más graves en la práctica, así que las
> comprobamos. Son **dos peticiones únicas a rutas canónicas conocidas**, no un
> barrido por diccionario. Si alguna responde con contenido, es un hallazgo de
> severidad relevante y lo verá en el reporte.

**Solo en modo auditoría, adicionalmente:**

| Petición | Origen |
|---|---|
| `GET` a cada ruta y endpoint del Anexo A.6 | Los que usted declaró |
| `GET` a cada activo adicional del Anexo A.5 | Los que usted declaró |
| `GET` a las rutas que su `robots.txt` marca como `Disallow` | Para verificar si tienen listado de directorios abierto |

Esa última línea merece una explicación: en **modo pasivo respetamos su
`robots.txt` y no solicitamos ninguna ruta marcada como `Disallow`**. En modo
auditoría, como usted autorizó el análisis de sus propios activos, sí las
revisamos —una ruta que se documenta públicamente como no rastreable pero queda
accesible es precisamente donde suele aparecer un listado de directorios—. Esta
diferencia queda registrada en la evidencia del hallazgo.

### Peticiones que **no** verá

- Ningún `POST`, `PUT`, `DELETE` ni `PATCH`. **Nunca enviamos datos a su sitio.**
- Ninguna ruta generada por diccionario, permutación o fuerza bruta.
- Ningún intento de autenticación ni de prueba de credenciales.
- Ningún parámetro malformado destinado a provocar un error o una inyección.
- Ninguna petición a la infraestructura de sus proveedores externos.

### Consultas que no tocan su infraestructura

Para descubrir subdominios consultamos el registro público de **Certificate
Transparency** (`crt.sh`). Esa consulta va a un tercero, no a sus servidores: no
aparecerá en sus registros.

### Características del tráfico

| Parámetro | Valor |
|---|---|
| Intervalo mínimo entre peticiones al mismo servidor | 2 segundos |
| Tope de peticiones por dominio | 60 |
| Tamaño máximo de respuesta leída | 5 MB |
| Máximo de redirecciones seguidas | 10 |
| Timeout por petición | 10 segundos |

### Si necesita detener el escaneo

Contacte al responsable del encargo o al contacto de emergencia indicados en el
[Anexo E](#anexo-e--responsables-del-encargo). El escaneo se detiene de inmediato,
sin dejar estado en su infraestructura.

---

## Anexo E — Responsables del encargo

### Por parte del cliente

| Rol | Nombre | Cargo | Contacto |
|---|---|---|---|
| Autoriza el diagnóstico | | | |
| Contacto técnico durante la ejecución | | | |
| Recibe el reporte | | | |
| Recibe alertas de monitoreo | | | |
| Responsable de la remediación | | | |

### Por parte de IDATA Chile

| Rol | Nombre | Contacto |
|---|---|---|
| Responsable del encargo | [[completar]] | [[completar]] |
| Analista asignado | [[completar]] | [[completar]] |
| Contacto para detener el escaneo | [[completar]] | [[completar]] |

---

*IDATA Chile — https://idatachile.com*
*Guía del servicio de Diagnóstico de Seguridad · versión 1.0 · julio de 2026*
