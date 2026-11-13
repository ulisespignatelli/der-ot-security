"""Lectura de capturas PCAP y PCAPNG sin dependencias externas.

Soporta enlaces Ethernet (con etiquetas VLAN), Linux cooked (SLL y SLL2),
IP sin encapsular y loopback de BSD; IPv4 e IPv6; segmentos TCP.
"""
import socket
import struct
from pathlib import Path

ETHERNET, NULL, RAW, SLL, SLL2, LOOP = 1, 0, 101, 113, 276, 108


def decode_frame(linktype, frame):
    """Devuelve (ip_origen, puerto, ip_destino, puerto, secuencia, banderas, datos, mac_origen) o None si no es TCP.

    mac_origen es None cuando el tipo de enlace no trae direcciones físicas.
    """
    mac = None
    if linktype == ETHERNET:
        if len(frame) < 14:
            return None
        ethertype, pos = struct.unpack(">H", frame[12:14])[0], 14
        mac = frame[6:12].hex(":")
        while ethertype in (0x8100, 0x88A8) and len(frame) >= pos + 4:   # etiquetas VLAN
            ethertype, pos = struct.unpack(">H", frame[pos + 2:pos + 4])[0], pos + 4
        if ethertype not in (0x0800, 0x86DD):
            return None
        packet = frame[pos:]
    elif linktype == SLL:
        packet = frame[16:]
    elif linktype == SLL2:
        packet = frame[20:]
    elif linktype in (NULL, LOOP):
        packet = frame[4:]
    elif linktype == RAW:
        packet = frame
    else:
        return None
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        ihl = (packet[0] & 0x0F) * 4
        if packet[9] != 6 or (struct.unpack(">H", packet[6:8])[0] & 0x1FFF):   # no TCP o fragmento
            return None
        total = struct.unpack(">H", packet[2:4])[0] or len(packet)
        src, dst = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
        segment = packet[ihl:total]
    elif version == 6 and len(packet) >= 40:
        if packet[6] != 6:
            return None
        length = struct.unpack(">H", packet[4:6])[0]
        src = socket.inet_ntop(socket.AF_INET6, packet[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, packet[24:40])
        segment = packet[40:40 + length]
    else:
        return None
    if len(segment) < 20:
        return None
    sport, dport, seq = struct.unpack(">HHI", segment[:8])
    offset = (segment[12] >> 4) * 4
    return src, sport, dst, dport, seq, segment[13], segment[offset:], mac


def read(path):
    """Genera (tiempo, ip_origen, puerto, ip_destino, puerto, secuencia, banderas, datos, mac_origen) por segmento TCP."""
    data = Path(path).read_bytes()
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
        return
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if magic not in formats:
        raise ValueError(f"{path}: no es un archivo PCAP ni PCAPNG")
    endian, unit = formats[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0xFFFF
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, caplen, _ = struct.unpack(endian + "IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + caplen]
        pos += 16 + caplen
        decoded = decode_frame(linktype, frame)
        if decoded:
            yield (sec + frac / unit, *decoded)


def _read_pcapng(data):
    pos, endian, interfaces = 0, "<", []
    while pos + 12 <= len(data):
        block_type = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if block_type == 0x0A0D0D0A:                          # encabezado de sección
            endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        length = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if length < 12 or pos + length > len(data):
            break
        body = data[pos + 8:pos + length - 4]
        if block_type == 1:                                   # descripción de interfaz
            linktype = struct.unpack(endian + "H", body[:2])[0]
            resolution, opt = 1e6, 8
            while opt + 4 <= len(body):
                code, size = struct.unpack(endian + "HH", body[opt:opt + 4])
                if code == 0:
                    break
                if code == 9 and size == 1:                   # resolución de tiempo
                    value = body[opt + 4]
                    resolution = float(2 ** (value & 0x7F)) if value & 0x80 else float(10 ** value)
                opt += 4 + (size + 3) // 4 * 4
            interfaces.append((linktype, resolution))
        elif block_type == 6 and len(body) >= 20:             # paquete
            iface, high, low, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
            if iface < len(interfaces):
                linktype, resolution = interfaces[iface]
                decoded = decode_frame(linktype, body[20:20 + caplen])
                if decoded:
                    yield (((high << 32) | low) / resolution, *decoded)
        pos += length


class TcpDeduplicator:
    """Descarta retransmisiones y duplicados de cada flujo TCP.

    Hace falta con capturas reales: una retransmisión, o una interfaz de
    loopback que entrega cada paquete dos veces, contaría como otra solicitud.
    """

    def __init__(self):
        self.next_seq = {}

    def new_data(self, flow, seq, flags, payload):
        if flags & 0x02:                                      # SYN: comienza una conexión
            self.next_seq.pop(flow, None)
        if not payload:
            return b""
        expected = self.next_seq.get(flow)
        if expected is not None:
            behind = (expected - seq) & 0xFFFFFFFF
            if behind < 0x80000000:                           # el segmento empieza antes de lo esperado
                if behind >= len(payload):
                    return b""
                payload, seq = payload[behind:], (seq + behind) & 0xFFFFFFFF
        self.next_seq[flow] = (seq + len(payload)) & 0xFFFFFFFF
        return payload
