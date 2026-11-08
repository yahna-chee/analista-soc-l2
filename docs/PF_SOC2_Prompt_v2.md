# PROMPT v2 · Investigador de incidentes SOC Nivel 2 (versión final replicable)

> Esta versión incorpora todas las decisiones y correcciones surgidas durante el desarrollo. Los apartados marcados con **[Lección]** existen porque su omisión causó un fallo real.

# ROL
Actúa como Ingeniero de Software Senior especializado en herramientas de ciberseguridad y como Analista SOC Nivel 2 con experiencia en respuesta a incidentes. Construye una aplicación web completa, funcional y lista para demostrar.

# CONTEXTO
Trabajo en una consultora de ciberseguridad en Estocolmo, Suecia, como Analista SOC Nivel 2. Un cliente reportó un posible incidente y entregó un Excel (.xlsx) con logs exportados de su SIEM. El archivo puede contener uno o varios incidentes mezclados.

# MISIÓN
A partir de los logs del SIEM: (1) buscar indicadores de compromiso (IoC), (2) correlacionar eventos, (3) establecer si hubo uno o varios incidentes y (4) generar un informe técnico profesional exportable en PDF.

# REGLA CRÍTICA: RIGOR ANALÍTICO
- No inventar hallazgos: cada conclusión se sustenta estrictamente en los registros del Excel cargado.
- Cada hallazgo cita su evidencia (Log_ID, timestamp, usuario, IP/host, acción, resultado) tal como aparece en el archivo.
- Si los datos no alcanzan, escribir "evidencia insuficiente" en vez de suponer.
- Distinguir siempre: **hecho observado** (log), **inferencia** (razonamiento) y **recomendación**.
- La IA solo redacta, explica y prioriza a partir de datos extraídos. Su prompt de sistema prohíbe añadir IPs, usuarios, hosts, fechas, Log_ID, comandos o hechos ausentes, y exige citar evidencias.
- **[Lección] Coherencia del informe:** ningún texto fijo puede afirmar algo que los datos contradigan. Ejemplo real: el informe decía "los logs no incluyen bytes transferidos" mientras los eventos traían `bytes_out`. Toda afirmación sobre datos disponibles o ausentes debe calcularse a partir del Excel, no escribirse a mano.
- No usar datos de ejemplo inventados: la app trabaja solo con el Excel cargado.

# ARQUITECTURA
- Un único archivo HTML (HTML/CSS/JS sin servidor), procesamiento 100 % en el navegador.
- Librerías por CDN (cdnjs) con versión fija: SheetJS 0.18.5, Chart.js 4.4.1, jsPDF 2.5.1 y jsPDF-AutoTable 3.8.2.
- Estado único en memoria; la configuración del informe en `localStorage`; la API key solo en `sessionStorage`.
- Tema oscuro tipo SOC, responsive, con mensajes de error claros y avisos tipo "toast".
- **[Lección]** Debe abrirse como archivo local o servirse por HTTPS desde un sitio propio (p. ej. GitHub Pages). Entornos que restringen conexiones externas bloquean la llamada a Gemini.

# NAVEGACIÓN (pestañas)
`1 Carga` · `Eventos` · `2 Análisis` · `3 Dashboard` · `4 Riesgos` · `5 Informe y PDF` · `Config`
- **[Lección]** Todas las pestañas deben funcionar aunque el análisis aún no se haya ejecutado (p. ej. la tabla de Eventos no debe fallar por campos sin inicializar). Al cargar cada fila, inicializar `sv=0, inc='', tc=[], rl=[]`.

# FUNCIONALIDADES

## 01. Carga de archivos
- Importar .xlsx por selector y drag & drop; soportar varias hojas con selector de hoja activa.
- Validar formato y mostrar errores claros, total de filas y rango temporal.
- **Mapeo de columnas** (campos: Log ID, Fecha/hora, Event ID, Host, Usuario, IP origen, Destino, Fuente, Descripción, Comando/proceso, Resultado, Severidad SIEM):
  - Autodetección por **nombre** (regex) y, si falla, por **contenido** de las primeras 100 filas (fechas, IPv4, IDs numéricos, valores de severidad, resultados), exigiendo ≥ 60 % de coincidencia y ≥ 3 valores.
  - **[Lección]** Cada lista desplegable debe mostrar, en este orden: opción "—", grupo **"Sugeridas para este campo"** (coinciden por nombre o contenido) y grupo **"Otras columnas libres"**. Las columnas ya asignadas a otro campo no se ofrecen. El panel de mapeo **no debe cerrarse** al cambiar una opción (persistir su estado abierto).
- Tabla de eventos con paginación (50 por página), búsqueda de texto, ordenamiento por columna, filtro por clic en gráficos y resaltado de sospechosos (barra lateral con color de severidad).
- **[Lección] Filtro de severidad SIEM dinámico:** el desplegable se construye con los **valores reales** de la columna Severidad (con conteo), ordenados Critical → High → Medium → Warning → Low → Informational y luego el resto. Nunca escribir las opciones a mano; así aparecen Informational, Warning y cualquier valor nuevo. Disponible en Eventos y en Dashboard.

## 02. Análisis de seguridad (reglas deterministas y visibles)
Cada regla disparada se muestra con nombre, severidad, táctica y técnica MITRE, y su evidencia desplegable.

| ID | Regla | Condición | Sev. | MITRE |
|---|---|---|---|---|
| SPRAY | Password spraying | ≥ 5 fallos y ≥ 3 cuentas desde una IP externa | Alto | Credential Access / T1110.003 |
| BRUTE | Fuerza bruta | ≥ 3 fallos desde una IP externa (sin cumplir SPRAY) | Alto | T1110.001 |
| SUCC | Acceso exitoso tras fallos | 4624 desde la misma IP externa tras los fallos | Crítico | Initial Access / T1078 |
| PRIV | Privilegios especiales desde IP externa | 4672 con IP externa | Alto | Privilege Escalation / T1078 |
| PS | PowerShell sospechoso | `-enc`/`EncodedCommand` o evento 4104 | Alto | Execution / T1059.001 |
| DISC | Reconocimiento interno | `net view/use/user/group`, Get-LocalGroupMember, Get-SmbShare | Medio | Discovery / T1135 |
| LAT | Movimiento lateral | Logon de red (`source=`) con cuenta ya comprometida | Alto | Lateral Movement / T1021.002 |
| SENS | Recurso sensible | 5140/5145 sobre Finance/Legal/Budget con cuenta comprometida | Alto | Collection / T1039 |
| STG | Staging/compresión | `tar/7z/rar`, Compress-Archive | Alto | Collection / T1560.001 |
| EXF | Salida por PowerShell | 5156 a destino externo iniciado por PowerShell | Alto | Exfiltration / T1041 |
| PER | Persistencia | 4698/7045 o ejecución desde ProgramData | Alto | Persistence / T1053.005, T1543.003 |
| WEB | Webshell | Petición con `cmd=`, `.aspx?`, `../`, `union select`, `<script` desde IP externa | Alto | Persistence / T1505.003 |
| IISP | Shell desde pool IIS | Cuenta `apppool` ejecutando cmd/powershell | Crítico | Execution / T1505.003, T1059.003 |
| WERR | Sondeo web | ≥ 5 errores 401/403/404/500 desde IP externa | Medio | Reconnaissance / T1595.002 |
| BEAC | Beaconing/exfiltración lenta | ≥ 10 conexiones del mismo usuario al mismo destino externo (se informa el intervalo medio) | Alto | Exfiltration / T1048, T1071.001 |
| SIEM | Severidad alta del SIEM sin regla | High/Critical no cubierta por otra regla | Medio | N/A |

- IP externa = no privada (RFC 1918). Los destinos con puerto se normalizan antes de evaluarlos.
- Extraer IoC: IPs (internas, externas y destinos), usuarios, hosts, procesos/comandos, rutas y URLs. Dominios y hashes solo si aparecen en los logs; si no, declararlo.
- **[Lección] Volumen saliente:** leer `bytes_out` cuando exista en el log. Calcular el total por hallazgo e incidente y mostrarlo en "Hecho observado" con formato `N bytes (X,X MiB)`. En los IoC, **un solo indicador agregado por destino** (no una fila por cada POST). Si no hay bytes, decir "volumen no disponible (evidencia insuficiente)". Nunca presentar el volumen como "datos robados": el éxito de la exfiltración se marca como no confirmado.
- **Correlación:** unión de hallazgos (union-find) por claves compartidas: IP origen, cuenta comprometida y, para persistencia, host. Cada incidente explica por qué se **unen** sus hallazgos y por qué se **separa** de los demás. Si dos incidentes comparten host sin vínculo por IP/cuenta, indicarlo como "evidencia insuficiente" y no unirlos.
- Línea de tiempo cronológica por incidente.

## 03. Dashboard
- KPI: eventos totales, sospechosos, incidentes, hallazgos críticos, hallazgos altos.
- Gráficos (Chart.js, interactivos con tooltip y clic que filtra Eventos): eventos en el tiempo (ventanas de 10 min, total vs sospechosos), distribución por criticidad (dona), top IPs, top usuarios, top hosts, tipo de evento (Event ID) y tácticas MITRE.
- Filtros: severidad de detección, **severidad SIEM** (dinámica, afecta también KPI total y serie temporal) e incidente.

## 04. Clasificación de riesgos
- Cada hallazgo e incidente: Crítico, Alto, Medio o Bajo, con justificación (impacto, activos, éxito del atacante, persistencia, alcance) y evidencia desplegable.
- **Criterio de incidente:** Crítico si hay acceso exitoso (SUCC) más una acción posterior (EXF, SENS, STG, PER, LAT o PS) o shell en servidor web; si no, la severidad máxima de sus hallazgos.

## 05. Informe técnico (en español, editable antes de exportar)
1. Portada · 2. Resumen ejecutivo (no técnico) · 3. Alcance y metodología · 4. Resumen de incidentes · 5. Hallazgos detallados (hecho observado / inferencia / MITRE / impacto / alcance / éxito del atacante / persistencia) · 6. Línea de tiempo · 7. IoC consolidados · 8. Activos y cuentas afectadas · 9. Impacto potencial · 10. Plan de acción (contención, erradicación, recuperación y hardening, con prioridad P1–P3 y responsables sugeridos) · 11. Limitaciones · 12. Anexos con evidencias.
- Las **limitaciones se generan según los datos**: fuentes únicas (solo Excel del SIEM), comandos ofuscados `[REDACTED]`, nombres de host inconsistentes (p. ej. DC-01/DC01), reputación de IPs no verificada, rango temporal acotado, y volumen transferido según exista o no `bytes_out`.
- Regenerar el informe vuelve a calcular los textos; avisar que las ediciones manuales previas se pierden.

## 06. Exportación a PDF
jsPDF + AutoTable: portada, índice, encabezados, tablas, **gráficos del dashboard incluidos** (capturados desde los canvas con fondo del tema), pie "Clasificación · Página X de Y".

# IA INTEGRADA (Gemini)
- Modelo **configurable** en Config (campo de texto). **[Lección]** Google retira modelos con frecuencia: valor por defecto `gemini-3.5-flash`; respaldo automático ante 404 con `gemini-3.5-flash`, `gemini-3.5-flash-lite` y `gemini-flash-latest`. Si el valor guardado pertenece a una familia 1.x/2.x, reemplazarlo por el predeterminado.
- Llamada `POST https://generativelanguage.googleapis.com/v1beta/models/{modelo}:generateContent`, API key en el encabezado `x-goog-api-key`, `temperature: 0.2`, `responseMimeType: application/json`, `maxOutputTokens: 16384`. Enviar `thinkingConfig: {thinkingBudget: 0}` solo para modelos 2.5 que no sean "pro".
- **Manejo de errores:** mostrar el código HTTP y el mensaje de Google (no un "falló" genérico) y, si se agotaron los respaldos, listar los modelos probados. Reintentar con espera ante 429/500/503; 404 pasa al siguiente modelo; 400/401/403 se informan de inmediato. Distinguir fallo de red, respuesta vacía, bloqueo (`blockReason`), JSON inválido y corte por `MAX_TOKENS`.
- Botón **"Probar conexión con Gemini"** en Config.
- Aceptar JSON envuelto en bloques ``` y convertir a texto cualquier campo de incidente que llegue como objeto.
- **Validación anti-alucinación:** si la respuesta cita una IP o un Log_ID que no existe en los datos, se descarta completa y la app sigue con el texto determinista, con aviso claro.
- Enviar solo hallazgos estructurados (reglas, conteos, rangos, IDs de evidencia, volumen `bytes_out_total` ya calculado), nunca el Excel.
- Prompt de sistema: analista SOC N2, solo español, solo con el JSON recibido, prohibido inventar IPs/usuarios/hosts/fechas/Log_ID/comandos, citar Log_ID, distinguir hecho/inferencia/recomendación, "evidencia insuficiente" cuando falte dato, responder únicamente `{"resumen":"…","incidentes":{"INC-01":"…"}}`.
- Indicador de progreso durante la llamada. Sin clave o con fallo, la app sigue operando con las reglas deterministas.
- **Orden de uso:** ejecutar la interpretación con IA **antes** de generar el PDF, para que el informe lo incluya.

# CONFIGURACIÓN
Campos persistidos en `localStorage`: Nombre del analista, Cliente, Organización/consultora, Clasificación del documento, Modelo de Gemini. Campo `password` para la API key (solo `sessionStorage`, sin espacios, nunca en pantalla ni en logs ni en el informe).

# SEGURIDAD Y PRIVACIDAD
- Sin API key en el código ni en el repositorio.
- Escapar todo texto proveniente del Excel antes de insertarlo en el HTML.
- Datos y capturas del repositorio/video: anonimizar IPs, usuarios y nombres de cliente reales.

# FORMA DE TRABAJO
1. Mostrar brevemente el plan de arquitectura y las reglas.
2. Entregar el código completo y funcional en un solo HTML.
3. **Probar** con un Excel generado de prueba antes de entregar: mapeo, severidades dinámicas, análisis, correlación, informe y manejo de error de Gemini simulado (404 con respaldo).

# CRITERIOS DE ACEPTACIÓN
- Las 6 funcionalidades operan de principio a fin con el Excel real.
- Ningún hallazgo carece de evidencia trazable; ningún texto fijo contradice los datos.
- Se determina si hay uno o varios incidentes y se justifica la unión o separación.
- Los desplegables de mapeo muestran solo columnas relevantes y libres; el filtro de severidad refleja los valores reales del archivo.
- Si Gemini falla, el mensaje indica la causa y la app continúa.
- El PDF es legible, completo, incluye gráficos y numeración de páginas.
- La interfaz es clara y no requiere instrucciones.

# ENTREGABLES
1. Informe PDF generado por la app (hallazgos, evidencias, criticidad, explicación técnica y plan de acción).
2. Video demostrativo de **máximo 5 minutos**: carga del Excel → análisis → dashboard → clasificación → interpretación con IA → informe → PDF. Recomendado: explicar la estructura sin datos (≈ 40 s) y luego hacer la prueba completa.
3. Publicación en GitHub: `index.html`, `README.md`, `docs/` (informe), datos de práctica anonimizados y enlace al video.
