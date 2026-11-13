# Cambios

## 0.8.1 (13 de noviembre de 2026)

- El sitio muestra el registro de auditoría de la última ejecución del laboratorio y permite
  alterarlo para ver cómo se rompe la cadena. La verificación corre en el navegador, recalculando
  SHA-256, así que funciona también en GitHub Pages.

## 0.8.0 (13 de noviembre de 2026)

- Registro de auditoría append-only encadenado por hashes, con `python -m sensor verify`.
  No es fail-closed: el sensor sigue detectando si no puede escribir, y lo informa.
- Política fijable por hash con `--policy-sha256`.
- `python -m sensor propose`: compara la política en uso con lo observado y lista los cambios
  marcando cuáles aflojan la detección. Nunca modifica la política vigente.
- Corpus de 21 tramas Modbus límite y malformadas, con sus pruebas.
- El laboratorio deja su propio registro auditable en `results/audit.jsonl`.

## 0.7.0 (13 de noviembre de 2026)

- Reproducción grabada en el sitio: la pestaña En vivo muestra al sensor analizando dos capturas
  de equipos reales, sin servidor y también en GitHub Pages.
- `tools/record_replay.py` graba el análisis de cualquier captura para el sitio.

## 0.6.0 (13 de noviembre de 2026)

- Reproducción de capturas en el panel en vivo: `python -m lab.live --replay`.
- La pestaña Resumen presenta el sensor y la validación sobre capturas de terceros.

## 0.5.0 (13 de noviembre de 2026)

- Regla R12: una dirección IP que aparece con otra dirección física (suplantación ARP).
- Direcciones físicas en el inventario y en la línea base.
- Validación con cuatro capturas del conjunto de datos de la Universidad de Coimbra.

## 0.4.0 (13 de noviembre de 2026)

- El sensor pasa a ser una herramienta independiente: `python -m sensor analyze | learn | live`.
- Inventario de activos y línea base aprendida, con las reglas R9, R10 y R11.
- Lector de PCAP y PCAPNG con VLAN, IPv4, IPv6 y descarte de retransmisiones.
- Captura en vivo desde una interfaz de red.
- El laboratorio evalúa cada ataque con política manual y con línea base aprendida.

## 0.3.0 (12 de noviembre de 2026)

- Escenarios de inyección de datos falsos (S7 y S8) y regla R8 de coherencia física.
- Familias de amenazas y tabla cruzada de tipo por zona.
- Panel en vivo integrado al sitio como pestaña.
- Modelo alineado con las seis zonas y la matriz del artículo de investigación.

## 0.2.0 (12 de noviembre de 2026)

- Laboratorio en tiempo real con panel web.

## 0.1.0 (12 de noviembre de 2026)

- Arquitectura de referencia con validador, modelo de amenazas, laboratorio grabado con seis
  ataques, análisis de consulta a expertos, indicadores de madurez y sitio.
