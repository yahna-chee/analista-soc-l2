# SOC L2 · Investigador de incidentes asistido por IA

Herramienta web (un solo HTML, sin servidor) que analiza exportaciones de logs SIEM en Excel, detecta patrones de ataque con reglas deterministas, correlaciona eventos en incidentes y genera un informe técnico en PDF.

- **Demo:** https://yahna-chee.github.io/analista-soc-l2/
- **Video:** [ASN2_video.mp4](https://github.com/yahna-chee/analista-soc-l2/blob/main/videos/ASN2_video.mp4)
- **Informe de ejemplo:** [Informe_SOC_L2_2026-11-04 (v4).pdf](https://github.com/yahna-chee/analista-soc-l2/blob/main/docs/Informe_SOC_L2_2026-11-04%20%28v4%29.pdf)

## Qué hace

- Carga Excel con mapeo automático de columnas
- Detección con 16 reglas deterministas (fuerza bruta, password spraying, movimiento lateral, exfiltración, persistencia, webshell y más), con mapeo a MITRE ATT&CK
- Correlación en incidentes, dashboard, clasificación de riesgos
- Informe editable y exportación a PDF
- Redacción opcional con Gemini, validada contra los datos

## Reglas de detección

Cada regla disparada se muestra con nombre, severidad, táctica y técnica MITRE, y su evidencia desplegable. Se considera IP externa toda dirección que no pertenece a rangos privados (RFC 1918).

| ID | Regla | Condición | Sev. | MITRE |
|---|---|---|---|---|
| SPRAY | Password spraying | ≥ 5 fallos y ≥ 3 cuentas desde una IP externa | Alto | Credential Access / T1110.003 |
| BRUTE | Fuerza bruta | ≥ 3 fallos desde una IP externa (sin cumplir SPRAY) | Alto | Credential Access / T1110.001 |
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

### Correlación y clasificación

- Los hallazgos se unen en un mismo incidente cuando comparten IP de origen, cuenta comprometida o, en persistencia, host. Cada incidente explica por qué se une o se separa de los demás.
- Un incidente es **Crítico** si combina un acceso exitoso (SUCC) con una acción posterior (EXF, SENS, STG, PER, LAT o PS) o si hay un shell en el servidor web. En otro caso hereda la severidad máxima de sus hallazgos.
- Si los datos no permiten concluir, el informe lo indica como «evidencia insuficiente».

## Uso

1. Abre `index.html` o la demo
2. Carga `sample-data/SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`
3. Ejecuta el análisis y revisa Dashboard e Informe
4. (Opcional) Pega tu API key de Gemini en Config

## Privacidad

Todo se procesa en el navegador. La API key se guarda solo en la sesión y a la IA solo se envían hallazgos estructurados, nunca el Excel.

## Stack

HTML/JS · SheetJS · Chart.js · jsPDF · Gemini API

