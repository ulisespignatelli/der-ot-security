"""Decodificación de Modbus/TCP. Solo lectura: no arma ni envía solicitudes."""
import struct

READ_HOLDING, WRITE_SINGLE, WRITE_MULTIPLE, DEVICE_ID = 3, 6, 16, 43
WRITE_CODES = {5, 6, 15, 16, 22, 23}
FUNCTION_NAMES = {
    1: "Leer bobinas", 2: "Leer entradas discretas", 3: "Leer registros de retención",
    4: "Leer registros de entrada", 5: "Escribir una bobina", 6: "Escribir un registro",
    7: "Leer estado de excepción", 8: "Diagnóstico", 11: "Contador de eventos",
    15: "Escribir varias bobinas", 16: "Escribir varios registros", 17: "Identificación del servidor",
    22: "Escritura con máscara", 23: "Leer y escribir registros", 43: "Identificación del dispositivo",
}


def split_adus(buffer):
    """Separa los ADU completos de un buffer. Devuelve (lista, resto).

    Si el contenido no parece Modbus/TCP (identificador de protocolo distinto
    de cero o longitud inválida) descarta el buffer.
    """
    adus = []
    while len(buffer) >= 8:
        pid, length = struct.unpack(">HH", buffer[2:6])
        if pid != 0 or not 2 <= length <= 254:
            return adus, b""
        total = 6 + length
        if len(buffer) < total:
            break
        adus.append(buffer[:total])
        buffer = buffer[total:]
    return adus, buffer


def parse_adu(adu):
    tid, _, _, unit = struct.unpack(">HHHB", adu[:7])
    return {"tid": tid, "unit": unit, "fc": adu[7], "data": adu[8:]}


def written_values(fc, data):
    """Devuelve [(registro, valor)] de una solicitud de escritura de registros."""
    if fc == WRITE_SINGLE and len(data) >= 4:
        return [struct.unpack(">HH", data[:4])]
    if fc == WRITE_MULTIPLE and len(data) >= 5:
        addr, count, nbytes = struct.unpack(">HHB", data[:5])
        if count and nbytes == 2 * count and len(data) >= 5 + nbytes:
            values = struct.unpack(f">{count}H", data[5:5 + nbytes])
            return [(addr + i, v) for i, v in enumerate(values)]
    return []


def device_identification(data):
    """Texto de identificación de una respuesta 43/14, o None."""
    if len(data) < 6 or data[0] != 14:
        return None
    parts, pos = [], 6
    for _ in range(data[5]):
        if pos + 2 > len(data):
            break
        size = data[pos + 1]
        parts.append(data[pos + 2:pos + 2 + size].decode("latin-1", "replace").strip())
        pos += 2 + size
    return " ".join(p for p in parts if p) or None
