"""Inversor fotovoltaico emulado con interfaz Modbus/TCP.

Mapa de registros (simplificado, inspirado en SunSpec):
  0  potencia activa (W)        solo lectura
  1  tensión (V x 10)           solo lectura
  2  frecuencia (Hz x 100)      solo lectura
  10 límite de potencia (%)     lectura y escritura
  11 conexión a red (1/0)       lectura y escritura
"""
import socket
import struct
import threading

from . import modbus

RATED_W = 5000
N_REGISTERS = 20


class Inverter:
    def __init__(self, host="127.0.0.1", port=0):
        self.regs = [0] * N_REGISTERS
        self.regs[1], self.regs[2], self.regs[10], self.regs[11] = 2200, 5000, 100, 1
        self._update()
        self.lock = threading.Lock()
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _update(self):
        limit = max(0, min(100, self.regs[10]))
        self.regs[0] = int(RATED_W * 0.8 * limit / 100) if self.regs[11] else 0

    def _accept(self):
        while self.running:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with conn:
            while True:
                try:
                    adu = modbus.recv_adu(conn)
                except OSError:
                    return
                if not adu:
                    return
                req = modbus.parse_adu(adu)
                try:
                    conn.sendall(modbus.build_adu(req["tid"], req["unit"], self.handle(req["fc"], req["data"])))
                except OSError:
                    return

    def handle(self, fc, data):
        def error(code):
            return bytes([fc | 0x80, code])

        with self.lock:
            if fc == modbus.READ_HOLDING and len(data) == 4:
                addr, count = struct.unpack(">HH", data)
                if count < 1 or addr + count > N_REGISTERS:
                    return error(2)
                return bytes([fc, count * 2]) + struct.pack(f">{count}H", *self.regs[addr:addr + count])
            if fc == modbus.WRITE_SINGLE and len(data) == 4:
                addr, value = struct.unpack(">HH", data)
                if addr not in (10, 11):
                    return error(2)
                self.regs[addr] = value
                self._update()
                return bytes([fc]) + data
            if fc == modbus.DEVICE_ID:
                vendor = b"Inversor emulado"
                return bytes([fc, 14, 1, 1, 0, 0, 1, 0, len(vendor)]) + vendor
            return error(1)

    def stop(self):
        self.running = False
        self.server.close()
