# aqui coletando IPs da rede do sandbox apos fechar a vpn


import nmap
import pandas as pd
from datetime import datetime


def escanear_rede_nmap(rede_alvo="10.10.20.0/24"):
    print(f"\n🔍 Varredura com Nmap na rede: {rede_alvo}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=rede_alvo, arguments="-sn")  # Ping scan (sem porta)

    dispositivos = []
    for host in scanner.all_hosts():
        if 'mac' in scanner[host]['addresses']:
            mac = scanner[host]['addresses']['mac']
        else:
            mac = "Desconhecido"

        dispositivos.append({
            "IP": host,
            "MAC": mac,
            "Estado": scanner[host].state()
        })

    return dispositivos


def salvar_em_excel(dispositivos):
    agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome_arquivo = f"dispositivos_rede_nmap_{agora}.xlsx"

    df = pd.DataFrame(dispositivos)
    df.to_excel(nome_arquivo, index=False)
    print(f"\n✅ Arquivo Excel gerado: {nome_arquivo}")


# Executa a varredura e salva os resultados
resultado = escanear_rede_nmap("10.10.20.0/24")

print("\n🖥️ Dispositivos encontrados:\n")
for d in resultado:
    print(f"IP: {d['IP']} | MAC: {d['MAC']} | Estado: {d['Estado']}")

salvar_em_excel(resultado)
