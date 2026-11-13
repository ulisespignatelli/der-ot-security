# Documentación del proyecto

Cómo está construido este repositorio, por qué se tomó cada decisión, cómo se validó y qué
relación guarda con el trabajo de investigación que lo originó.

El [README](README.md) explica qué hace el proyecto y cómo usarlo. Este documento explica cómo
se hizo y por qué, y está dirigido a quien tenga que evaluarlo, continuarlo o defenderlo.

---

## 1. Panorama

El repositorio tiene tres capas que se apoyan una en otra:

| Capa | Qué es | Dónde |
|---|---|---|
| **Sensor** | Una herramienta de detección pasiva de Modbus/TCP, utilizable sobre cualquier captura o interfaz de red | `sensor/` |
| **Laboratorio** | Equipos emulados que generan tráfico y ataques para poner a prueba el sensor | `lab/` |
| **Modelo** | Arquitectura de referencia, amenazas e indicadores de madurez que dan contexto al sensor | `model/`, `tools/` |

Y un sitio (`web/`, `docs/`) que reúne los resultados de las tres.

| Cifra | Valor |
|---|---|
| Código propio | 2.611 líneas de Python, 904 de HTML con JavaScript |
| Dependencias externas | Ninguna, salvo scapy para capturar en vivo fuera de Linux |
| Reglas de detección | 12 |
| Pruebas automáticas | 40 |
| Zonas del modelo | 6 del trabajo de investigación, más TI corporativa como contexto |
| Amenazas modeladas | 27: 6 críticas, 10 altas, 11 medias |
| Escenarios de ataque | 8, más uno de operación normal |
| Tramas del corpus | 21 casos límite y malformados |

---

## 2. Arquitectura del software

### Flujo de datos

```
                                   ┌─────────────────────────────────┐
captura .pcap / .pcapng ──────────►│                                 │
interfaz de red (puerto espejo) ──►│  sensor/pcap.py                 │  decodifica enlace, IP, TCP
switch emulado del laboratorio ───►│  sensor/modbus.py               │  decodifica Modbus/TCP
                                   │  sensor/engine.py               │  inventario + 12 reglas
                                   └───────────┬─────────────────────┘
                                               │
                     ┌─────────────────────────┼─────────────────────────┐
                     ▼                         ▼                         ▼
              inventario de activos      alertas                 registro de auditoría
                     │                         │                  (sensor/audit.py)
                     ▼                         ▼
          sensor/baseline.py  ───►  sensor/propose.py  ───►  política revisada por un ingeniero
```

### Módulos

| Archivo | Responsabilidad |
|---|---|
| `sensor/pcap.py` | Lee PCAP y PCAPNG; decodifica Ethernet con VLAN, Linux cooked, IP sin encapsular y loopback; IPv4 e IPv6; descarta retransmisiones y duplicados TCP |
| `sensor/modbus.py` | Separa y decodifica unidades Modbus/TCP. Solo lectura: no contiene código capaz de armar una solicitud |
| `sensor/engine.py` | Procesa un segmento por vez. Arma el inventario y aplica las reglas. Sirve igual para una captura y para tráfico en vivo |
| `sensor/baseline.py` | Aprende una política a partir de una captura de operación normal |
| `sensor/propose.py` | Compara una política en uso con lo observado y propone cambios, sin aplicarlos |
| `sensor/audit.py` | Registro append-only encadenado por hashes, y su verificación |
| `sensor/capture.py` | Captura desde una interfaz: `AF_PACKET` en Linux, scapy en el resto |
| `sensor/__main__.py` | Línea de comandos: `analyze`, `learn`, `propose`, `live`, `verify` |
| `lab/inverter_sim.py` | Inversor fotovoltaico emulado con registros de potencia, límite y conexión |
| `lab/tap.py` | Switch emulado con puerto espejo. Copia cada paquete al archivo y al sensor |
| `lab/run_lab.py` | Ejecuta los 8 ataques, guarda capturas y resultados, y deja su registro de auditoría |
| `lab/live.py` | Laboratorio continuo y servidor local del panel; también reproduce capturas grabadas |
| `tools/validate_architecture.py` | Marca los flujos que cruzan zonas sin un conducto declarado |
| `tools/risk_matrix.py` | Calcula riesgo y nivel de cada amenaza |
| `tools/expert_consensus.py` | Acuerdo entre especialistas: W de Kendall y correlación de Spearman |
| `tools/record_replay.py` | Graba el análisis de una captura para reproducirlo en el sitio sin servidor |
| `web/build.py` | Reúne modelos y resultados y genera `docs/index.html` |

### Una sola fuente de verdad

Los datos viven en archivos (`model/*.json`, `results/*.json`), los programas los procesan y el
sitio los muestra. Nada se escribe a mano en el HTML: `web/build.py` inserta los datos en la
plantilla. Cambiar una amenaza o volver a correr el laboratorio y regenerar el sitio alcanza para
que todo quede al día, sin posibilidad de que una tabla contradiga a otra.

---

## 3. Decisiones de diseño

### 3.1 Sin dependencias externas

El proyecto usa solo la biblioteca estándar de Python. El formato PCAP, el protocolo Modbus y los
gráficos del sitio están escritos a mano.

**Por qué.** Cualquiera clona el repositorio y lo ejecuta sin instalar nada, lo que importa para
que el trabajo sea reproducible por un tercero. En un entorno industrial, además, cada dependencia
es una superficie de ataque y un trámite de aprobación.

**Qué cuesta.** Algunas piezas son más simples que las de una herramienta comercial: el lector de
capturas no reordena segmentos TCP fuera de orden ni reensambla fragmentos IP.

### 3.2 El sensor no puede transmitir

El paquete `sensor/` no contiene ninguna llamada capaz de enviar datos por la red. Una prueba
automática revisa el código fuente y falla si aparece alguna.

**Por qué.** El argumento central del trabajo de investigación es que el monitoreo activo puede
desestabilizar equipos industriales antiguos. Que el sensor *no pueda* transmitir es más fuerte
que prometer que no lo hace, y es verificable por quien audite el código.

**Qué cuesta.** El sensor nunca va a poder consultar un equipo para completar el inventario, que
es lo que haría una herramienta activa. Lo que no pasa por la red, no lo ve.

### 3.3 El registro de auditoría no es fail-closed

Si el registro no se puede escribir, el sensor **sigue analizando**, cuenta los registros perdidos
y lo informa al terminar.

**Por qué.** Esta decisión es la inversión deliberada de un patrón tomado de un proyecto de
seguridad de agentes de IA, donde lo correcto es lo opuesto: un portón que no puede auditar debe
bloquear, porque es preferible frenar a actuar sin registro. En una red eléctrica, dejar de
analizar porque se llenó un disco sería quedarse ciego justo cuando hace falta ver. La seguridad
física manda sobre la informática.

**Qué cuesta.** Un atacante que llene el disco puede provocar un hueco en el registro. El hueco
queda informado, pero el registro de ese período se pierde.

### 3.4 Dos políticas complementarias

Cada escenario del laboratorio se evalúa dos veces: con una política escrita a mano y con una
línea base que el sensor aprende solo. Las dos detectan 6 de 8 ataques, pero no los mismos.

**Por qué.** Mostrar las dos juntas deja ver algo que ninguna sola muestra: la línea base aprendida
detecta la consigna válida enviada con la identidad del maestro (S6), porque en la operación normal
nadie escribe; si escribir fuera habitual, no la vería. La regla de coherencia física (S7) solo
existe en la política manual, porque requiere conocer el equipo. Son capas distintas, no
alternativas.

### 3.5 `propose` separado de `learn`

`learn` escribe una política desde cero. `propose` compara una política en uso con lo observado,
lista los cambios marcando cuáles **aflojan** la detección, y nunca modifica la política vigente.

**Por qué.** Escribir una política de mínimo privilegio desde cero es difícil, y por eso la gente
termina permitiendo todo. Que la herramienta proponga y el ingeniero decida mantiene el criterio
humano donde corresponde. Lo que la política permite y la captura no muestra se informa pero no se
quita: que algo no aparezca en media hora de tráfico no prueba que no se use.

### 3.6 Emulación antes que equipos reales

El laboratorio emula el inversor, el switch y la pasarela. El tráfico Modbus es real, los equipos no.

**Por qué.** No había acceso a equipos industriales. La emulación permite ejecutar ataques
destructivos (desconectar el inversor, inundarlo) que sobre un equipo real requerirían autorización
y un banco de pruebas.

**Qué cuesta.** Un equipo emulado se comporta como lo programó quien lo escribió. Por eso la
validación con capturas de terceros (sección 4.4) no es un extra, es lo que impide que el proyecto
sea un sistema probándose contra sí mismo.

### 3.7 Un solo protocolo

El sensor entiende Modbus/TCP y nada más.

**Por qué.** Es el protocolo de los inversores fotovoltaicos, que son el activo central de la zona
DER, la única que el laboratorio evalúa. Agregar IEC 60870-5-104 o DNP3 sin profundizar en ninguno
habría dado tres decodificadores superficiales.

**Qué cuesta.** Las redes de distribución reales usan IEC 104 o DNP3 para telecontrol, así que el
sensor no cubre hoy la zona de subestaciones.

### 3.8 Un sitio generado, sin framework

`docs/index.html` es un único archivo con sus estilos, su JavaScript y sus datos adentro.

**Por qué.** Se abre con doble clic, se publica en GitHub Pages sin compilación y no envejece con
las versiones de ninguna biblioteca. El verificador de la cadena de auditoría recalcula SHA-256 en
el navegador, así que funciona sin servidor.

---

## 4. Cómo se validó

La validación tiene cuatro niveles, y cada uno encuentra cosas que los otros no.

| Nivel | Qué prueba | Qué encontró |
|---|---|---|
| Pruebas automáticas | Que cada pieza hace lo que dice | Regresiones durante el desarrollo |
| Corpus de tramas | Que el decodificador no falla con entradas hostiles | Un error en los propios datos de prueba |
| Laboratorio emulado | Que las reglas detectan ataques conocidos | Los límites del monitoreo pasivo (S6, S8) |
| Capturas de terceros | Que funciona con tráfico que no generó el proyecto | Un punto ciego real: el intermediario por suplantación ARP |

### 4.1 Pruebas automáticas

40 pruebas que cubren el modelo, el laboratorio grabado y en vivo, la reproducción, el lector de
capturas, la línea base, las propuestas, el registro de auditoría y la línea de comandos. Entre
ellas hay varias que no comprueban que algo funcione, sino que algo **no** pase:

- que el paquete `sensor/` no contenga código capaz de transmitir;
- que la operación normal no genere ninguna alerta;
- que los escenarios indetectables sigan siendo indetectables, para que una regla nueva no los
  "arregle" por casualidad;
- que una propuesta nunca modifique la política de entrada.

### 4.2 Corpus de tramas malformadas

`tests/corpus/modbus_edge_cases.json` reúne 21 tramas límite: encabezados truncados, longitudes
declaradas falsas, identificadores de protocolo inválidos, cantidades de bytes mentidas,
identificaciones desbordadas, varias unidades en un mismo segmento. Una prueba las pasa todas por
el decodificador y por el motor de reglas, y verifica que ninguna falle ni se interprete de más.

El corpus encontró un error en la primera ejecución, aunque no donde se esperaba: estaba en los
datos de prueba, no en el sensor. Dos casos declaraban longitudes incoherentes por un descuido al
escribirlos a mano. Se corrigió haciendo que la longitud se calcule sola, salvo en los casos que
declaran una falsa a propósito.

### 4.3 Laboratorio emulado

Una pasarela consulta al inversor cada 100 ms. Un switch emulado copia el tráfico a un archivo
PCAP y al sensor. Ocho ataques, más veinte segundos de operación normal para medir falsos
positivos.

| Escenario | Ataque | Política manual | Línea base aprendida |
|---|---|---|---|
| S1 | Escritura no autorizada del límite de potencia | Detectado | Detectado |
| S2 | Reconocimiento | Detectado | Detectado |
| S3 | Consigna fuera de rango desde el maestro autorizado | Detectado | Detectado |
| S4 | Inundación de solicitudes | Detectado | Detectado |
| S5 | Desconexión del inversor | Detectado | Detectado |
| S6 | Consigna válida con identidad del maestro | No detectado | Detectado |
| S7 | Datos falsos físicamente imposibles | Detectado | No detectado |
| S8 | Datos falsos coherentes con el modelo | No detectado | No detectado |

**0 alertas en 398 solicitudes de operación normal**, con las dos políticas.

Los escenarios que no se detectan son parte del resultado, no una falla pendiente. S8 reproduce en
pequeño el hallazgo fundacional sobre inyección de datos falsos: un atacante que conoce el modelo
del equipo puede construir valores falsos que son físicamente posibles y, por lo tanto,
indistinguibles en la red. Es el argumento empírico a favor de la defensa en profundidad.

### 4.4 Capturas de terceros

Cuatro capturas públicas del *Cyber-security Modbus ICS dataset* de la Universidad de Coimbra,
tomadas en un banco de pruebas con equipos reales.

| Captura (30 minutos) | Contenido | Resultado | Primera alerta |
|---|---|---|---|
| `eth2dump-clean-0,5h_1.pcap` | Operación normal | Sin alertas | — |
| `eth2dump-mitm-change-5m-0,5h_1.pcap` | Intermediario por suplantación ARP | Detectado: R12 | Segundo 301 |
| `eth2dump-mitm-change-15m-0,5h_1.pcap` | Intermediario por suplantación ARP | Detectado: R12 | Segundo 301 |
| `eth2dump-modbusQueryFlooding1m-0,5h_1.pcap` | Inundación de consultas Modbus | Detectado: R1, R2, R3, R7 | Segundo 299 |

**Esta prueba cambió el sensor.** En la primera ejecución, el ataque de intermediario pasó sin
ninguna alerta. El motivo es que ese ataque no altera direcciones IP ni produce Modbus inválido:
el atacante se hace pasar por el equipo de supervisión mediante suplantación ARP, y lo único que
cambia es la dirección física. De ahí salió la regla R12, que mira la capa de enlace. Sin probar
con tráfico ajeno, ese punto ciego no se habría encontrado.

Las capturas no se incluyen en el repositorio. La reproducción grabada del sitio guarda lo que el
sensor observó (solicitudes, activos y alertas a lo largo del tiempo), no el tráfico.

### 4.5 Integración continua

Cada subida a GitHub ejecuta en una máquina limpia: el validador de arquitectura, las 40 pruebas,
el laboratorio completo, la generación del sitio, el aprendizaje de una línea base, un análisis con
auditoría, la verificación de dos cadenas de auditoría y una propuesta de política.

---

## 5. Reglas de detección

| Regla | Detecta | Técnica | Necesita |
|---|---|---|---|
| R1 | Maestro Modbus no autorizado | T0846 | Lista de maestros |
| R2 | Escritura desde un maestro no autorizado | T0855 | Lista de maestros |
| R3 | Consigna fuera de los límites | T0836 | Límites manuales o aprendidos |
| R4 | Orden de desconexión del inversor | T0816 | Registro de conexión |
| R5 | Solicitud de identificación o diagnóstico | T0888 | Nada |
| R6 | Barrido de registros | T0846 | Nada |
| R7 | Tasa de solicitudes anómala | T0814 | Límite de tasa |
| R8 | Telemetría físicamente incoherente | T0856 | Modelo del equipo |
| R9 | Código de función ausente en la línea base | T0855 | Línea base |
| R10 | Escritura a un registro sin antecedentes | T0836 | Línea base |
| R11 | Esclavo ausente en la línea base | T0846 | Línea base |
| R12 | Dirección IP con otra dirección física | T0830 | Nada |

Cada regla está asociada a una técnica de MITRE ATT&CK for ICS. Tres de ellas (R5, R6 y R12)
pueden dispararse sin ninguna configuración, lo que permite usar el sensor sobre una captura
desconocida y obtener algo útil de entrada: en las capturas de Coimbra, R12 detecta el
intermediario sin política alguna. Las demás necesitan saber qué es normal en esa red, sea a mano
o aprendido.

---

## 6. Cronología del desarrollo

| Versión | Qué agregó | Por qué |
|---|---|---|
| 0.1 | Arquitectura con validador, modelo de amenazas, laboratorio con 6 ataques, análisis de consulta a especialistas, indicadores de madurez y sitio | Llevar a código las etapas futuras del trabajo |
| 0.2 | Laboratorio en tiempo real con panel web | Ver la alerta en el momento del ataque, no en una tabla posterior |
| 0.3 | Inyección de datos falsos (S7 y S8), regla R8, familias de amenazas, panel integrado al sitio | La inyección de datos falsos es el antecedente más citado del trabajo y no estaba evaluada |
| 0.4 | El sensor pasa a ser herramienta independiente: inventario, línea base aprendida, lector robusto, captura en vivo, reglas R9 a R11 | Separar lo que sirve en una red real de lo que solo sirve en el laboratorio |
| 0.5 | Regla R12 y validación con capturas de Coimbra | Probar el sensor con tráfico que no generó el proyecto |
| 0.6 | Reproducción de capturas en el panel | Mostrar el sensor trabajando sobre tráfico real |
| 0.7 | Reproducción grabada en el sitio | Que se vea en GitHub Pages, sin instalar nada |
| 0.8 | Auditoría encadenada, política fijada por hash, `propose`, corpus de tramas | Rigor de ingeniería y trazabilidad, apuntando a IEC 62443 SR 6.1 |
| 0.8.1 | Verificador de la cadena en el sitio | Hacer tangible una propiedad difícil de explicar en palabras |

El historial completo está en [CHANGELOG.md](CHANGELOG.md).

---

## 7. Relación con el trabajo de investigación

### 7.1 El trabajo

> U. G. Pignatelli, M. E. Casco y S. Roatta, "Ciberseguridad en Redes Eléctricas Inteligentes con
> Generación Distribuida: Revisión Estructurada y Matriz de Controles para Entornos IT/OT",
> 14° Congreso Nacional de Ingeniería en Informática / Sistemas de Información (CONAIISI 2026),
> Resistencia, Chaco, Argentina, noviembre de 2026.

El artículo está en [`paper/`](paper/). Presenta una revisión estructurada de la literatura sobre
ciberseguridad en redes de distribución con generación distribuida, y una matriz preliminar que
asocia activos, amenazas, impactos y controles con los marcos de referencia que los respaldan. El
propio artículo señala que esa matriz **no ha sido validada**, y define como etapas futuras la
arquitectura de referencia (2), el modelo formal de amenazas (3), la evaluación empírica por
emulación y consulta a especialistas (4) y los indicadores de madurez (5).

Este repositorio es el prototipo de esas etapas. **No forma parte de los resultados del artículo.**

### 7.2 Qué proviene del trabajo y qué agrega el prototipo

| Elemento | Origen |
|---|---|
| Las seis zonas: AMI, subestaciones, centro de control, telecomunicación y pasarelas, DER, proveedores | Sección 3 del trabajo |
| Amenazas, impactos, controles y marcos de cada zona | Tabla 1 del trabajo |
| Las cinco familias de amenazas | Sección 4 del trabajo |
| Zona de TI corporativa | Agregada por el prototipo, solo como contexto de la convergencia IT/OT |
| Activos, direcciones, conductos y flujos de la arquitectura | Escenario hipotético del prototipo |
| Probabilidad e impacto de cada amenaza | Propuesta del prototipo: la matriz del trabajo no pondera |
| Técnica de MITRE ATT&CK for ICS de cada amenaza | Propuesta del prototipo |
| Asignación de cada amenaza a una familia | Propuesta del prototipo |
| Amenazas A26 y A27 | Extienden a DER la inyección de datos falsos que la Tabla 1 nombra en AMI |

Cada amenaza de `model/threats.json` declara su origen en el campo `source`.

Un criterio de trazabilidad guía todo el modelo: el artículo organiza la matriz **por zona**,
porque cada activo queda en una sola y eso favorece la correspondencia con marcos como IEC 62443,
que razona en zonas y conductos. El análisis **por tipo de amenaza** es el de la Sección 4. El
prototipo conserva los dos ejes y los cruza en una tabla, sin reemplazar uno por otro.

### 7.3 Estado de cada etapa

La distinción importa: el prototipo constituye un **avance** sobre las etapas futuras, no su
cumplimiento.

| Etapa | Qué existe | Qué falta para darla por cumplida |
|---|---|---|
| **2. Arquitectura de referencia** | Formato de datos para zonas, activos y conductos, y un validador que encuentra 3 de 15 flujos que violan la segmentación | Relevar una arquitectura real; la actual es un escenario hipotético |
| **3. Modelo de amenazas** | 27 amenazas por zona y por familia, con controles, marcos, ponderación y técnica de ATT&CK | Justificar las ponderaciones y definir escenarios de impacto sobre la operación eléctrica |
| **4. Evaluación por emulación** | Laboratorio con 8 ataques y sensor validado con capturas de equipos reales | Cubrir zonas además de DER y protocolos además de Modbus/TCP |
| **4. Consulta a especialistas** | El análisis estadístico implementado y probado | Hacer la consulta: las respuestas actuales son sintéticas |
| **5. Indicadores de madurez** | Cuestionario de 18 preguntas en 6 dominios, con puntaje y prioridades | Fundamentar los indicadores y validarlos con organizaciones del sector |

El laboratorio evalúa 8 de las 27 amenazas, todas de la zona DER. Las amenazas de AMI,
subestaciones, centro de control, telecomunicación y proveedores figuran como "no evaluado" en el
sitio, deliberadamente.

### 7.4 Qué puede afirmarse y qué no

Esta sección existe para que nadie, dentro o fuera del equipo, describa el proyecto de más.

**Puede afirmarse:**

- Que las cuatro etapas futuras tienen una implementación funcional y reproducible.
- Que existe una primera evaluación empírica de la zona DER, con datos sintéticos y con capturas
  públicas de un banco de pruebas, que es el tipo de validación que el propio artículo propone.
- Que el monitoreo pasivo detecta 6 de 8 ataques emulados y los 3 ataques de las capturas de
  terceros, sin falsos positivos en el tráfico normal de ninguna de las dos fuentes.
- Que los ataques no detectados delimitan empíricamente el alcance del monitoreo pasivo de red.

**No puede afirmarse:**

- Que la matriz esté validada. Se validó una porción: 8 de 27 amenazas, en una sola zona.
- Que la arquitectura describa una red de la provincia de Santa Fe. Es un escenario hipotético.
- Que haya habido consulta a especialistas. Los datos son sintéticos y el sitio lo aclara.
- Que el sensor haya sido probado en una red en operación. No lo fue.
- Que el proyecto sea un cortafuegos o un sistema de prevención. Es un sistema de detección: no
  bloquea nada y no puede hacerlo.

### 7.5 Trazabilidad con los marcos

| Marco | Dónde aparece |
|---|---|
| IEC 62443 | Modelo de zonas y conductos del validador; referencias por zona; SR 6.1 en el registro de auditoría |
| MITRE ATT&CK for ICS | Técnica asociada a cada amenaza y a cada regla de detección |
| NISTIR 7628, IEC 62351, IEC 61850, NIST SP 800-82 Rev. 3, NIST CSF 2.0, IEEE 2030.7 | Asignados a cada zona según la Tabla 1 del trabajo |
| C2M2 y NIST CSF 2.0 | Inspiración de los indicadores de madurez |

### 7.6 Influencias externas

El registro de auditoría encadenado, la política fijada por hash, la separación entre aprender y
proponer, y el corpus de casos aislados son patrones tomados de
[VT-Agent-Firewall](https://github.com/ValentinTorassa/VT-Agent-Firewall), un proyecto de
seguridad de agentes de IA. No se copió código: son decisiones de ingeniería aplicables a
cualquier herramienta con política y registro. La postura fail-closed de ese proyecto se invirtió
a propósito, por las razones de la sección 3.3.

---

## 8. Limitaciones

Las limitaciones completas están en el [README](README.md#limitaciones). Las que más condicionan
las conclusiones:

1. **El sensor solo entiende Modbus/TCP.** No cubre IEC 60870-5-104, DNP3 ni IEC 61850.
2. **La validación externa es acotada:** cuatro capturas de un único conjunto de datos público.
3. **El laboratorio evalúa una sola zona** de las seis del modelo.
4. **La arquitectura, las ponderaciones y las respuestas de especialistas** son hipotéticas,
   provisionales y sintéticas respectivamente.
5. **La línea base acepta como normal todo lo que observa.** Aprenderla durante un incidente lo
   deja autorizado.
6. **El registro de auditoría detecta manipulaciones, no las impide.** Quien pueda escribir el
   archivo puede borrarlo entero.
7. **La captura en vivo se probó en Linux.** La variante para Windows no está probada.

---

## 9. Cómo reproducir todo

```bash
python -m unittest                      # 40 pruebas
python tools/validate_architecture.py   # flujos que violan la segmentación
python tools/risk_matrix.py             # matriz de riesgo
python -m lab.run_lab                   # 8 ataques, capturas y registro de auditoría
python -m sensor verify results/audit.jsonl
python web/build.py                     # regenera el sitio
python -m lab.live                      # laboratorio en tiempo real
```

Para repetir la validación con capturas de terceros, descargar `captures1_v2.zip` del
[conjunto de datos de Coimbra](https://github.com/tjcruz-dei/ICS_PCAPS) y seguir los comandos de
la sección correspondiente del README.

---

*Documento correspondiente a la versión 0.9.0 del repositorio. Prototipo de investigación: el
sensor fue validado con un laboratorio emulado y con cuatro capturas públicas, y no fue probado en
una red en operación.*
