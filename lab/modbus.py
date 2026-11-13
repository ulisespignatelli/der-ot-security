"""Cliente y utilidades de Modbus/TCP para los equipos emulados del laboratorio.

La decodificación es la del sensor; lo que se agrega acá es la parte que
transmite, que el sensor no tiene.
"""
import socket
import struct

from sensor.modbus import (DEVICE_ID, READ_HOLDING, WRITE_CODES, WRITE_MULTIPLE,  # noqa: F401
                           WRITE_SINGLE, parse_adu, split_adus)


def build_adu(tid, unit, pdu):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


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
