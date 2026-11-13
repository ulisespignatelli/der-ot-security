"""Switch emulado con puerto espejo.

Cada puerto de entrada representa el puerto físico donde está conectado un
equipo, y tiene asignada la dirección IP de ese equipo. El tráfico se reenvía
al inversor y se copia a un archivo PCAP, igual que un puerto espejo: el
sensor nunca interviene en la comunicación.
"""
import socket
import struct
import threading
import time


class PcapWriter:
    def __init__(self, path):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.lock = threading.Lock()
        self.count = 0

    def write(self, src_ip, src_port, dst_ip, dst_port, seq, payload):
        tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, seq & 0xFFFFFFFF, 0, 5 << 4, 0x18, 65535, 0, 0)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0, 64, 6, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        frame = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + tcp + payload
        now = time.time()
        with self.lock:
            self.fh.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6), len(frame), len(frame)) + frame)
            self.count += 1

    def close(self):
        with self.lock:
            self.fh.close()


class Tap:
    def __init__(self, target, target_ip, identities, modbus_port=502):
        """identities: lista de direcciones IP; se abre un puerto de entrada por cada una."""
        self.target, self.target_ip, self.modbus_port = target, target_ip, modbus_port
        self.writer = None
        self.tamper = None     # función(ip_origen, puerto, ip_destino, puerto, datos) -> datos: intermediario en el enlace
        self.on_packet = None  # función(ts, ip_origen, puerto, ip_destino, puerto, datos): copia en vivo
        self.ports = {}
        self.servers = []
        self._ephemeral = 49152
        for ip in identities:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(16)
            self.ports[ip] = srv.getsockname()[1]
            self.servers.append(srv)
            threading.Thread(target=self._accept, args=(srv, ip), daemon=True).start()

    def start_capture(self, path):
        self.writer = PcapWriter(path)

    def stop_capture(self):
        writer, self.writer = self.writer, None
        if writer:
            time.sleep(0.05)
            writer.close()
            return writer.count
        return 0

    def _accept(self, srv, ip):
        while True:
            try:
                client, _ = srv.accept()
            except OSError:
                return
            self._ephemeral += 1
            upstream = socket.create_connection(self.target)
            for s in (client, upstream):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sport = self._ephemeral
            threading.Thread(target=self._pipe, args=(client, upstream, ip, sport, self.target_ip, self.modbus_port), daemon=True).start()
            threading.Thread(target=self._pipe, args=(upstream, client, self.target_ip, self.modbus_port, ip, sport), daemon=True).start()

    def _pipe(self, src, dst, src_ip, src_port, dst_ip, dst_port):
        seq = 1
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                tamper = self.tamper
                if tamper:
                    data = tamper(src_ip, src_port, dst_ip, dst_port, data)
                writer = self.writer
                if writer:
                    try:
                        writer.write(src_ip, src_port, dst_ip, dst_port, seq, data)
                    except ValueError:
                        pass
                listener = self.on_packet
                if listener:
                    listener(time.time(), src_ip, src_port, dst_ip, dst_port, data)
                seq += len(data)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()

    def stop(self):
        for s in self.servers:
            s.close()
