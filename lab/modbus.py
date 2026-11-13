"""Utilidades mínimas de Modbus/TCP, sin dependencias externas."""
import socket
import struct

READ_HOLDING, WRITE_SINGLE, WRITE_MULTIPLE, DEVICE_ID = 3, 6, 16, 43
WRITE_CODES = {5, 6, 15, 16}


def build_adu(tid, unit, pdu):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def split_adus(buffer):
    """Separa los ADU completos de un buffer. Devuelve (lista, resto)."""
    adus = []
    while len(buffer) >= 8:
        length = struct.unpack(">H", buffer[4:6])[0]
        total = 6 + length
        if length < 2 or len(buffer) < total:
            break
        adus.append(buffer[:total])
        buffer = buffer[total:]
    return adus, buffer


def parse_adu(adu):
    tid, _, _, unit = struct.unpack(">HHHB", adu[:7])
    return {"tid": tid, "unit": unit, "fc": adu[7], "data": adu[8:]}


def recv_adu(sock):
    header = _recv_exact(sock, 6)
    if not header:
        return None
    body = _recv_exact(sock, struct.unpack(">H", header[4:6])[0])
    return header + body if body else None


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class Client:
    """Cliente Modbus/TCP mínimo para el SCADA emulado y los escenarios."""

    def __init__(self, host, port, timeout=3.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.tid = 0

    def request(self, pdu, unit=1):
        self.tid = (self.tid + 1) & 0xFFFF
        self.sock.sendall(build_adu(self.tid, unit, pdu))
        reply = recv_adu(self.sock)
        return parse_adu(reply) if reply else None

    def read_holding(self, address, count):
        return self.request(struct.pack(">BHH", READ_HOLDING, address, count))

    def write_single(self, address, value):
        return self.request(struct.pack(">BHH", WRITE_SINGLE, address, value))

    def device_id(self):
        return self.request(bytes([DEVICE_ID, 14, 1, 0]))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
