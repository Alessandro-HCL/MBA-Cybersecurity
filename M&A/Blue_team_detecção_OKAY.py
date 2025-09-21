

import subprocess
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import ipaddress
import os
import platform


# testes realizados e detectados:
# sudo hping3 -a 1.1.1.1 -S -p 80 192.168.198.131 (IP spoofing)
# # sudo hping3 -t 1 -S -p 80 192.168.198.131 (TTL alterado)
# sudo nmap -sS -p- 192.168.198.131 (TCP sys scan) - demora mais para ser processado - aqui só tenho que ajustar pois está detectando syn flood
# sudo hping3 -S -p 80 --flood 192.168.198.131 (syn flood) -
# aqui uma variação do comando acima para controlar o nivel de stress - sudo hping3 -S -p 80 -i u5000 192.168.198.51
# OBS: se baixa de 5000 stressa mais e se aumentar de 5000, vai diminuiindo a carga
# sudo hping3 --udp -p 53 --flood 192.168.198.131 (UDP Flood)
# timeout 1 openssl s_client -connect 192.168.198.131:443 (TLS Handshake incompleto)

# ataques ainda em testes:
# testar DNS Tunneling
# for i in {1..10}; do
#   dig TXT $(openssl rand -hex 20).malicio.so @192.168.198.131
# done

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

    return "Tipo desconhecido"

def obter_caminho_tshark():
    if os.name == "nt":
        return r"C:\Program Files\Wireshark\tshark.exe"
    else:
        return "tshark"

def listar_interfaces():
    print("🔍 Interfaces disponíveis para captura (use o número ou nome exibido):\n")
    tshark_path = obter_caminho_tshark()
    try:
        result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print("❌ Tshark não encontrado. Verifique se está instalado no sistema.")

def capturar_pacotes(interface_id, duracao, nome_arquivo):
    tshark_path = obter_caminho_tshark()
    print(f"\n[+] Capturando pacotes na interface '{interface_id}' por {duracao} segundos...")
    subprocess.run([
        tshark_path, "-i", interface_id,
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
                'src_port': int(src_port) if src_port else 0,
                'dst_port': int(dst_port) if dst_port else 0,
                'ip_len': ip_len,
                'ttl': ttl,
                'tcp_flags': tcp_flags,
                'protocolo': protocolo
            })
    return pd.DataFrame(linhas)

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

# Execução principal
if __name__ == "__main__":
    print("🔍 Modo Monitoramento Ativo com Captura Tshark")
    listar_interfaces()
    interface_id = input("\nDigite o número ou nome da interface a ser usada: ").strip()
    duracao = input("⏱️ Duração da captura (segundos): ").strip() or "60"
    nome_arquivo = "captura_monitoramento.pcap"
    capturar_pacotes(interface_id, duracao, nome_arquivo)
    df = analisar_pcap(nome_arquivo)
    analisar_anomalias(df)
    print("\n✅ Monitoramento finalizado.")
