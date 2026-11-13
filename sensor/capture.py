"""Captura pasiva desde una interfaz de red.

En Linux usa un socket AF_PACKET (requiere permisos de administrador). En
otros sistemas usa scapy si está instalado; en Windows scapy necesita Npcap.
El socket solo se usa para recibir.
"""
import socket
import sys
import time

from . import pcap


def sniff(interface, on_segment, stop=lambda: False, port=502):
    """Llama a on_segment(tiempo, ip_origen, puerto, ip_destino, puerto, secuencia, banderas, datos, mac_origen)."""
    if sys.platform.startswith("linux"):
        return _sniff_linux(interface, on_segment, stop, port)
    return _sniff_scapy(interface, on_segment, stop, port)


def _sniff_linux(interface, on_segment, stop, port):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        raise SystemExit("La captura en vivo necesita permisos de administrador (sudo).")
    try:
        sock.bind((interface, 0))
    except OSError as error:
        raise SystemExit(f"No se pudo abrir la interfaz {interface}: {error}")
    sock.settimeout(0.5)
    try:
        while not stop():
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            decoded = pcap.decode_frame(pcap.ETHERNET, frame)
            if decoded and port in (decoded[1], decoded[3]):
                on_segment(time.time(), *decoded)
    finally:
        sock.close()


def _sniff_scapy(interface, on_segment, stop, port):
    try:
        from scapy.all import IP, TCP, Ether, IPv6, sniff as scapy_sniff
    except ImportError:
        raise SystemExit("En este sistema la captura en vivo necesita scapy (pip install scapy) "
                         "y, en Windows, Npcap (https://npcap.com).")

    def handle(packet):
        if not packet.haslayer(TCP):
            return
        ip = packet[IP] if packet.haslayer(IP) else packet[IPv6] if packet.haslayer(IPv6) else None
        if ip is None:
            return
        tcp = packet[TCP]
        on_segment(float(packet.time), ip.src, tcp.sport, ip.dst, tcp.dport, tcp.seq, int(tcp.flags), bytes(tcp.payload),
                   getattr(packet, "src", None) if packet.haslayer(Ether) else None)

    scapy_sniff(iface=interface, filter=f"tcp port {port}", prn=handle, store=False,
                stop_filter=lambda _packet: stop())
