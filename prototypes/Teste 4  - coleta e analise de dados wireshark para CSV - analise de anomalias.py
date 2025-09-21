import pyshark
import csv
from collections import defaultdict

# Caminho do arquivo de captura
capture2 = pyshark.FileCapture(
    r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_SYNFlood.pcapng"
    # r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_TTL.pcapng"
    # r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_IPspoofing.pcapng"
    # r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_spoofing.pcapng"
    # r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_MACspoofing4.pcapng"
    # r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura.pcapng"
)



# Dicionários para detecção de anomalias
ip_to_mac = defaultdict(set)  # Para detectar ARP Spoofing
mac_to_ip = defaultdict(set)  # Para detectar MAC sendo usado com múltiplos IPs
mac_count = defaultdict(int)  # Para contar pacotes por MAC
syn_count = defaultdict(int)  # Para detectar escaneamento de portas
retransmission_count = defaultdict(int)  # Para monitorar retransmissões TCP

print("🔎 Iniciando análise de anomalias...")

# Cria/abre um arquivo CSV para escrita
with open('packets2.csv', 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)

    # Escreve o cabeçalho (colunas)
    writer.writerow([
        'frame_time', 'frame_len', 'tcp_time_delta', 'tcp_retransmission',
        'src_eth', 'dst_eth', 'type_eth', 'oui_eth_src', 'oui_eth_dst', 'lg_eth', 'ig_eth',
        'src_ip', 'dst_ip', 'proto_ip', 'ttl_ip', 'flags_ip', 'len_ip', 'checksum_ip',
        'srcport_tcp', 'dstport_tcp', 'flags_tcp', 'seq_tcp', 'ack_tcp', 'window_size_tcp', 'len_tcp',
        'srcport_udp', 'dstport_udp', 'length_udp', 'checksum_udp',
        'dns_qry_name', 'dns_qry_type', 'dns_a', 'dns_aaaa', 'dns_resp_name', 'dns_flags_response',
        'http_request_method', 'http_host', 'http_request_uri', 'http_user_agent', 'http_response_code',
        'tls_record_version', 'tls_handshake_type', 'tls_sni',
        'arp_src_ip', 'arp_dst_ip', 'arp_src_mac', 'arp_dst_mac', 'arp_opcode',
        'dhcp_message_type', 'dhcp_hostname', 'dhcp_requested_ip'
    ])

    # Itera sobre os pacotes na captura
    for packet in capture2:
        frame_time = frame_len = tcp_time_delta = tcp_retransmission = None
        src_eth = dst_eth = type_eth = oui_eth_src = oui_eth_dst = lg_eth = ig_eth = None
        src_ip = dst_ip = proto_ip = ttl_ip = flags_ip = len_ip = checksum_ip = None
        srcport_tcp = dstport_tcp = flags_tcp = seq_tcp = ack_tcp = window_size_tcp = len_tcp = None
        srcport_udp = dstport_udp = length_udp = checksum_udp = None
        dns_qry_name = dns_qry_type = dns_a = dns_aaaa = dns_resp_name = dns_flags_response = None
        http_request_method = http_host = http_request_uri = http_user_agent = http_response_code = None
        tls_record_version = tls_handshake_type = tls_sni = None
        arp_src_ip = arp_dst_ip = arp_src_mac = arp_dst_mac = arp_opcode = None
        dhcp_message_type = dhcp_hostname = dhcp_requested_ip = None

        # #teste
        # if src_ip and src_eth:
        #     mac_to_ip[src_eth].add(src_ip)

        # Informações gerais do quadro (Frame)
        if hasattr(packet, 'frame'):
            frame_time = getattr(packet.frame, 'time', None)
            frame_len = getattr(packet.frame, 'len', None)

        # Camada Ethernet (L2)
        if hasattr(packet, 'eth'):
            src_eth = getattr(packet.eth, 'src', None)
            dst_eth = getattr(packet.eth, 'dst', None)
            mac_count[src_eth] += 1  # Contagem de MACs

        # Camada ARP (L2)
        if hasattr(packet, 'arp'):
            arp_src_ip = getattr(packet.arp, 'src_proto_ipv4', None)
            arp_dst_ip = getattr(packet.arp, 'dst_proto_ipv4', None)
            arp_src_mac = getattr(packet.arp, 'src_hw_mac', None)
            arp_dst_mac = getattr(packet.arp, 'dst_hw_mac', None)
            arp_opcode = getattr(packet.arp, 'opcode', None)

            if arp_src_ip and arp_src_mac:
                ip_to_mac[arp_src_ip].add(arp_src_mac)

        # Camada IP (L3)
        if hasattr(packet, 'ip'):
            src_ip = getattr(packet.ip, 'src', None)
            dst_ip = getattr(packet.ip, 'dst', None)
            ttl_ip = getattr(packet.ip, 'ttl', None)
            # aqui analisando TTL - Enviar pacotes com TTL extremamente baixo.
            try:
                if ttl_ip is not None and int(ttl_ip) <= 5:
                    print(f"⚠️ TTL Alterado detectado: Pacote de {src_ip} para {dst_ip} com TTL = {ttl_ip}")
            except ValueError:
                continue

        # Camada TCP (L4)
        if hasattr(packet, 'tcp'):
            srcport_tcp = getattr(packet.tcp, 'srcport', None)
            dstport_tcp = getattr(packet.tcp, 'dstport', None)
            flags_tcp = getattr(packet.tcp, 'flags', None)

            # if "SYN" in flags_tcp and "ACK" not in flags_tcp:
            #     syn_count[src_ip] += 1

            if "SYN" in flags_tcp and "ACK" not in flags_tcp and dstport_tcp:
                syn_count[src_ip] += 1
                syn_count[src_ip + "_ports"] = syn_count.get(src_ip + "_ports", set())
                syn_count[src_ip + "_ports"].add(dstport_tcp)

            if hasattr(packet.tcp, 'analysis_retransmission'):
                retransmission_count[src_ip] += 1

        # Camada DNS (L7)
        if hasattr(packet, 'dns'):
            dns_qry_name = getattr(packet.dns, 'qry_name', None)

        # Camada HTTP/HTTPS (L7)
        if hasattr(packet, 'http'):
            http_user_agent = getattr(packet.http, 'user_agent', None)

        # Camada TLS/SSL (L7)
        if hasattr(packet, 'tls'):
            tls_handshake_type = getattr(packet.tls, 'handshake_type', None)

        # Camada DHCP (L7)
        if hasattr(packet, 'dhcp'):
            dhcp_message_type = getattr(packet.dhcp, 'option_dhcp', None)

        # Escreve a linha no CSV
        writer.writerow([
            frame_time, frame_len, tcp_time_delta, tcp_retransmission,
            src_eth, dst_eth, type_eth, oui_eth_src, oui_eth_dst, lg_eth, ig_eth,
            src_ip, dst_ip, proto_ip, ttl_ip, flags_ip, len_ip, checksum_ip,
            srcport_tcp, dstport_tcp, flags_tcp, seq_tcp, ack_tcp, window_size_tcp, len_tcp,
            srcport_udp, dstport_udp, length_udp, checksum_udp,
            dns_qry_name, dns_qry_type, dns_a, dns_aaaa, dns_resp_name, dns_flags_response,
            http_request_method, http_host, http_request_uri, http_user_agent, http_response_code,
            tls_record_version, tls_handshake_type, tls_sni,
            arp_src_ip, arp_dst_ip, arp_src_mac, arp_dst_mac, arp_opcode,
            dhcp_message_type, dhcp_hostname, dhcp_requested_ip
        ])

# Detecta anomalias ao final da análise
for ip, macs in ip_to_mac.items():
    if len(macs) > 1:
        print(f"⚠️ ARP Spoofing detectado: O IP {ip} está associado a múltiplos MACs: {macs}")
#teste
for mac, count in mac_count.items():
    if count > 1000 and len(mac_to_ip[mac]) > 1:
        print(f"⚠️ MAC Spoofing provável: MAC {mac} com tráfego elevado ({count} pacotes) e múltiplos IPs: {mac_to_ip[mac]}")

# # Detecção mais precisa de MAC Spoofing - teste
# for mac, ips in mac_to_ip.items():
#     if len(ips) > 1:
#         print(f"⚠️ MAC Spoofing possível: O MAC {mac} está associado a múltiplos IPs: {ips}")

for mac, count in mac_count.items():
    if count > 1000:
        print(f"⚠️ MAC Spoofing detectado: O MAC {mac} enviou {count} pacotes.")

# for ip, count in syn_count.items():
#     if count > 50:
#         print(f"⚠️ Escaneamento de portas detectado do IP {ip} ({count} SYNs).")

print("\n🔎 Verificando escaneamento de portas...")
for ip in syn_count:
    print("teste")
    if "_ports" in ip:
        continue
    ip_ports_key = ip + "_ports"
    num_portas = len(syn_count[ip_ports_key])
    if num_portas > 30:
        print(f"⚠️ Escaneamento de portas detectado do IP {ip} ({num_portas} portas diferentes com SYN).")


for ip, count in retransmission_count.items():
    if count > 20:
        print(f"⚠️ Retransmissões TCP anormais do IP {ip} ({count} retransmissões).")

print("✅ Análise concluída e CSV gerado!")
