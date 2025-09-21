




import paramiko
import pandas as pd
import re
from scapy.all import ARP, Ether, srp
import nmap
import requests
from datetime import datetime
import time
import os


def buscar_fabricante(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        return "Desconhecido"
    return "Desconhecido"


def escanear_arp(rede_alvo):
    print(f"\n🔍 Varredura ARP em: {rede_alvo}")
    try:
        pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rede_alvo)
        resposta, _ = srp(pacote, timeout=2, verbose=0)
        dispositivos = []
        for _, r in resposta:
            fabricante = buscar_fabricante(r.hwsrc)
            dispositivos.append({
                "IP": r.psrc,
                "MAC": r.hwsrc,
                "Fabricante": fabricante
            })
        return dispositivos
    except Exception as e:
        print(f"⚠️ Erro na varredura ARP: {e}")
        return []


def escanear_icmp_nmap(rede_alvo):
    print(f"\n🔁 Fallback ICMP (Nmap): {rede_alvo}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=rede_alvo, arguments="-sn")
    dispositivos = []
    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', 'Desconhecido')
        fabricante = buscar_fabricante(mac)
        dispositivos.append({
            "IP": host,
            "MAC": mac,
            "Fabricante": fabricante
        })
    return dispositivos


def enriquecer_com_nmap(dispositivos):
    scanner = nmap.PortScanner()
    for dispositivo in dispositivos:
        ip = dispositivo["IP"]
        print(f"🔎 Nmap {ip}")
        try:
            scanner.scan(ip, arguments="-O -T4 --top-ports 10")
            host_data = scanner[ip]
            osmatch = host_data.get("osmatch", [])
            dispositivo["OS"] = osmatch[0]["name"] if osmatch else "Desconhecido"
            portas = []
            if 'tcp' in host_data:
                for porta, info in host_data['tcp'].items():
                    if info['state'] == 'open':
                        portas.append(f"{porta}/{info['name']}")
            dispositivo["Portas Abertas"] = ", ".join(portas) if portas else "Nenhuma"
        except Exception as e:
            dispositivo["OS"] = "Erro"
            dispositivo["Portas Abertas"] = "Erro"
    return dispositivos


def coletar_detalhes_cisco(dispositivo, usuario, senha):
    ip = dispositivo["IP"]
    print(f"🔐 SSH Cisco {ip}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False, timeout=5)
        shell = ssh.invoke_shell()
        shell.settimeout(10)

        def enviar_comando(cmd, espera=4):
            shell.send(cmd + "\n")
            time.sleep(espera)
            return shell.recv(9999).decode(errors="ignore")

        shell.send("terminal length 0\n")
        time.sleep(1)

        version = enviar_comando("show version")
        vlan = enviar_comando("show vlan brief")
        cdp = enviar_comando("show cdp neighbors")
        erros = enviar_comando("show interfaces counters errors")
        macs = enviar_comando("show mac address-table")
        inventory = enviar_comando("show inventory")
        mem = enviar_comando("sh memory summary | i Processor")
        cpu = enviar_comando("show processes cpu")
        intbrief = enviar_comando("show ip interface brief")

        ssh.close()

        hostname = re.search(r'(\S+) uptime is', version)
        serial = re.search(r'Processor board ID (\S+)', version)
        modelo = re.search(r'Cisco IOS Software, (\S+)', version)
        ios = re.search(r'Version ([\d\.\(\)A-Z]+)', version)
        uptime = re.search(r'uptime is ([^\n]+)', version)

        interfaces_up = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s+up\s+up', intbrief, re.M)
        qtd_interfaces = len(interfaces_up)

        cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', cpu)
        cpu_percent = cpu_match.group(1) if cpu_match else "Desconhecido"

        mem_match = re.search(r'^Processor\s+\S+\s+(\d+)\s+(\d+)', mem, re.M)
        if mem_match:
            total = int(mem_match.group(1))
            used = int(mem_match.group(2))
            mem_percent = f"{(used / total) * 100:.1f}"
        else:
            mem_percent = "Desconhecido"

        vlans = re.findall(r'^(\d+)\s+[\w-]+\s+active', vlan, re.M)
        vlans_ativas = ", ".join(vlans) if vlans else "Nenhuma"

        cdp_vizinhos = re.findall(r'^(\S+)\s+\n\s+Gig \d+/\d+', cdp, re.M)
        vizinhos = ", ".join(cdp_vizinhos) if cdp_vizinhos else "Nenhum"

        erros_entrada = re.findall(r'^(\S+)\s+\d+\s+(\d+)\s+(\d+)', erros, re.M)
        erros_totais = sum(int(e[1]) + int(e[2]) for e in erros_entrada)
        resumo_erros = f"{erros_totais} erro(s)" if erros_totais else "Nenhum erro"

        modulos = re.findall(r'NAME: \"([^\"]+)\", DESCR: \"([^\"]+)\"\s+PID: (\S+),.*SN: (\S+)', inventory)
        modulos_info = modulos[0][0] if modulos else "Nenhum módulo"

        macs_dinamicos = re.findall(r'DYNAMIC\s+(\S+)', macs)
        qtd_mac = len(macs_dinamicos)

        dispositivo.update({
            "Cisco_Hostname": hostname.group(1) if hostname else "Desconhecido",
            "Serial": serial.group(1) if serial else "Desconhecido",
            "Modelo": modelo.group(1) if modelo else "Desconhecido",
            "IOS": ios.group(1) if ios else "Desconhecido",
            "Uptime": uptime.group(1).strip() if uptime else "Desconhecido",
            "Interfaces Ativas": qtd_interfaces,
            "VLANs Ativas": vlans_ativas,
            "CDP Vizinhos": vizinhos,
            "Erros de Interface": resumo_erros,
            "Módulos": modulos_info,
            "MACs Ativos": qtd_mac,
            "Uso de CPU (%)": cpu_percent,
            "Uso de Memória (%)": mem_percent
        })

    except Exception as e:
        dispositivo.update({k: "Erro" for k in [
            "Cisco_Hostname", "Serial", "Modelo", "IOS", "Uptime",
            "Interfaces Ativas", "VLANs Ativas", "CDP Vizinhos",
            "Erros de Interface", "Módulos", "MACs Ativos",
            "Uso de CPU (%)", "Uso de Memória (%)"]})


# def salvar_em_excel(dispositivos):
#     agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#     nome_arquivo = f"relatorio_cisco_completo_{agora}.xlsx"
#     df = pd.DataFrame(dispositivos)
#     df.to_excel(nome_arquivo, index=False)
#     print(f"\n✅ Planilha salva como: {nome_arquivo}")

def salvar_em_excel(dispositivos):
    agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome_arquivo = f"relatorio_cisco_completo_{agora}.xlsx"

    # Cria a pasta "inventario" se não existir
    pasta = "inventario"
    os.makedirs(pasta, exist_ok=True)

    # Caminho completo do arquivo
    caminho_completo = os.path.join(pasta, nome_arquivo)

    df = pd.DataFrame(dispositivos)
    df.to_excel(caminho_completo, index=False)
    print(f"\n✅ Planilha salva como: {caminho_completo}")


# Execução principal
# if __name__ == "__main__":
#     rede_input = input("Digite a rede a ser escaneada (ex: 192.168.198.0/24): ").strip()
#     usuario_ssh = "admin"
#     senha_ssh = "cisco12345"
#     todos_dispositivos = []
#
#     dispositivos = escanear_arp(rede_input)
#     if not dispositivos:
#         dispositivos = escanear_icmp_nmap(rede_input)
#     dispositivos = enriquecer_com_nmap(dispositivos)
#     for d in dispositivos:
#         if "cisco" in d["OS"].lower() or "ios" in d["OS"].lower():
#             coletar_detalhes_cisco(d, usuario_ssh, senha_ssh)
#     todos_dispositivos.extend(dispositivos)
#
#     salvar_em_excel(todos_dispositivos)


import ipaddress

def entrada_e_subrede(entrada):
    try:
        ipaddress.IPv4Network(entrada)
        return True
    except:
        return False

if __name__ == "__main__":
    rede_input = input("Digite a rede ou IP a ser escaneado (ex: 192.168.198.0/24 ou 192.168.198.51): ").strip()
    usuario_ssh = "admin"
    senha_ssh = "cisco12345"
    todos_dispositivos = []

    if entrada_e_subrede(rede_input):
        # Rede CIDR
        dispositivos = escanear_arp(rede_input)
        if not dispositivos:
            dispositivos = escanear_icmp_nmap(rede_input)
    else:
        # IP único
        print("🔍 Escaneando IP único...")
        dispositivos = escanear_icmp_nmap(rede_input)  # ARP em IP direto pode falhar fora da mesma subrede

    dispositivos = enriquecer_com_nmap(dispositivos)

    for d in dispositivos:
        if "cisco" in d["OS"].lower() or "ios" in d["OS"].lower():
            coletar_detalhes_cisco(d, usuario_ssh, senha_ssh)

    todos_dispositivos.extend(dispositivos)
    salvar_em_excel(todos_dispositivos)



