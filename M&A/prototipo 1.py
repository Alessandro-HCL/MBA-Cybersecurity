# aqui varrendo a rede local
# funcionando


# from scapy.all import ARP, Ether, srp
# import requests
# import pandas as pd
# from datetime import datetime
#
#
# def buscar_fabricante(mac):
#     try:
#         url = f"https://api.macvendors.com/{mac}"
#         response = requests.get(url, timeout=3)
#         if response.status_code == 200:
#             return response.text
#     except:
#         return "Desconhecido"
#     return "Desconhecido"
#
#
# def escanear_rede(rede_alvo="192.168.1.0/24"):
#     print(f"\n🔍 Varredura na rede: {rede_alvo}")
#
#     pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rede_alvo)
#     resposta, _ = srp(pacote, timeout=2, verbose=0)
#
#     dispositivos = []
#     for _, r in resposta:
#         fabricante = buscar_fabricante(r.hwsrc)
#         dispositivos.append({
#             "IP": r.psrc,
#             "MAC": r.hwsrc,
#             "Fabricante": fabricante
#         })
#
#     return dispositivos
#
#
# def salvar_em_excel(dispositivos):
#     agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#     nome_arquivo = f"dispositivos_rede_{agora}.xlsx"
#
#     df = pd.DataFrame(dispositivos)
#     df.to_excel(nome_arquivo, index=False)
#
#     print(f"\n✅ Arquivo Excel gerado: {nome_arquivo}")
#
#
# # Executa o scan e salva
# # resultado = escanear_rede("192.168.1.0/24")
# resultado = escanear_rede("192.168.1.0/24")
# print("\n🖥️ Dispositivos encontrados:\n")
# for d in resultado:
#     print(f"IP: {d['IP']} | MAC: {d['MAC']} | Fabricante: {d['Fabricante']}")
#
# salvar_em_excel(resultado)



from scapy.all import ARP, Ether, srp
import requests
import pandas as pd
from datetime import datetime
import nmap

def buscar_fabricante(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        return "Desconhecido"
    return "Desconhecido"

# def escanear_rede_arp(rede_alvo="192.168.1.0/24"):
def escanear_rede_arp(rede_alvo="192.168.198.0/24"):
    print(f"\n🔍 Varredura ARP na rede: {rede_alvo}")

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

def enriquecer_com_nmap(dispositivos):
    scanner = nmap.PortScanner()

    for dispositivo in dispositivos:
        ip = dispositivo["IP"]
        print(f"🔎 Escaneando {ip} com Nmap...")

        try:
            scanner.scan(ip, arguments="-O -T4 --top-ports 10")
            host_data = scanner[ip]

            # Hostname
            hostname = host_data.hostname() if host_data.hostname() else "Desconhecido"
            dispositivo["Hostname"] = hostname

            # Sistema Operacional
            osmatch = host_data.get("osmatch", [])
            sistema = osmatch[0]["name"] if osmatch else "Desconhecido"
            dispositivo["OS"] = sistema

            # Portas abertas
            portas = []
            if 'tcp' in host_data:
                for porta, info in host_data['tcp'].items():
                    if info['state'] == 'open':
                        portas.append(f"{porta}/{info['name']}")
            dispositivo["Portas Abertas"] = ", ".join(portas) if portas else "Nenhuma"

        except Exception as e:
            dispositivo["Hostname"] = "Erro"
            dispositivo["OS"] = "Erro"
            dispositivo["Portas Abertas"] = "Erro"

    return dispositivos

def salvar_em_excel(dispositivos):
    agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome_arquivo = f"dispositivos_detalhados_{agora}.xlsx"

    df = pd.DataFrame(dispositivos)
    df.to_excel(nome_arquivo, index=False)
    print(f"\n✅ Arquivo Excel gerado: {nome_arquivo}")

# Execução
# rede = "192.168.1.0/24"
rede = "192.168.198.0/24"
dispositivos_encontrados = escanear_rede_arp(rede)
dispositivos_detalhados = enriquecer_com_nmap(dispositivos_encontrados)

print("\n🖥️ Resultados Finais:\n")
for d in dispositivos_detalhados:
    print(f"{d['IP']} | {d['MAC']} | {d['Fabricante']} | {d['Hostname']} | {d['OS']} | {d['Portas Abertas']}")

salvar_em_excel(dispositivos_detalhados)

