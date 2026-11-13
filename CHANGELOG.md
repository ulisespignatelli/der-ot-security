# Cambios

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
