# import pyshark
# import csv
#
#
# # aqui abrindo o arquivo do wireshark
# capture2 = pyshark.FileCapture(
#     r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura2.pcapng"
# )
#
# # Cria/abre um arquivo CSV para escrita
# with open('packets2.csv', 'w', newline='', encoding='utf-8') as csvfile:
#     writer = csv.writer(csvfile)
#
#     # Escreve o cabeçalho (colunas)
#     writer.writerow(['src_eth', 'dst_eth', 'type_eth', 'oui_eth_src', 'oui_eth_dst','lg_eth','ig_eth', 'src_ip', 'dst_ip','proto_ip', 'ttl_ip', 'flags_ip','len_ip', 'checksum_ip', 'srcport_tcp', 'dstport_tcp', 'flags_tcp', 'seq_tcp','ack_tcp', 'window_size_tcp','len_tcp'])
#     for packet in capture2:
#         if hasattr(packet, 'eth'):# Uma forma simples de evitar o erro é verificar se a camada IP existe antes de tentar acessá-la. Assim, se o pacote não tiver IPv4, o Python não chamará packet.ip.
#             #Camada de Enlace (Ethernet - L2) - Ajuda a identificar dispositivos suspeitos, endereços MAC falsificados (MAC Spoofing) e ataques ARP spoofing.
#             src_eth = packet.eth.src
#             dst_eth = packet.eth.dst
#             type_eth = packet.eth.type #Tipo do protocolo na camada superior (ex.: IPv4 = 0x0800, IPv6 = 0x86dd, ARP = 0x0806)
#             oui_eth_src = packet.eth.src_oui_resolved #Fabricante da placa de rede
#             oui_eth_dst = packet.eth.dst_oui_resolved #Fabricante da placa de rede
#             lg_eth = packet.eth.dst_lg #Indica se o MAC de destino é localmente administrado
#             ig_eth = packet.eth.dst_ig # Indica se o MAC de destino é multicast
#             src_ip = packet.ip.src#Endereço IP de origem
#             dst_ip = packet.ip.dst#Endereço IP de destino
#             proto_ip = packet.ip.proto#Protocolo da camada de transporte (ex.: TCP = 6, UDP = 17, ICMP = 1)
#             ttl_ip = packet.ip.ttl
#             flags_ip = packet.ip.flags#Flags de fragmentação
#             len_ip = packet.ip.len#Tamanho total do pacote
#             checksum_ip = packet.ip.checksum#Checksum do cabeçalho IP
#             srcport_tcp = packet.tcp.srcport
#             dstport_tcp = packet.tcp.dstport
#             flags_tcp = packet.tcp.flags
#             seq_tcp = packet.tcp.seq
#             ack_tcp = packet.tcp.ack
#             window_size_tcp = packet.tcp.window_size
#             len_tcp = packet.tcp.len
#
#
#
#
#         # Escreve a linha no CSV
#         writer.writerow([src_eth, dst_eth, type_eth, oui_eth_src, oui_eth_dst, lg_eth, ig_eth, src_ip, dst_ip, proto_ip, ttl_ip, flags_ip, len_ip, checksum_ip, srcport_tcp, dstport_tcp, flags_tcp, seq_tcp, ack_tcp, window_size_tcp, len_tcp])


import pyshark
import csv

# Caminho do arquivo de captura
capture2 = pyshark.FileCapture(
    r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura2.pcapng"
)

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
        # Inicializa variáveis com valores padrão
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

        # Informações gerais do quadro (Frame)
        if hasattr(packet, 'frame'):
            frame_time = getattr(packet.frame, 'time', None)  # Timestamp do pacote
            frame_len = getattr(packet.frame, 'len', None)  # Tamanho total do quadro

        # Camada Ethernet (L2)
        if hasattr(packet, 'eth'):
            src_eth = getattr(packet.eth, 'src', None)
            dst_eth = getattr(packet.eth, 'dst', None)
            type_eth = getattr(packet.eth, 'type', None)
            oui_eth_src = getattr(packet.eth, 'src_oui_resolved', None)
            oui_eth_dst = getattr(packet.eth, 'dst_oui_resolved', None)
            lg_eth = getattr(packet.eth, 'dst_lg', None)
            ig_eth = getattr(packet.eth, 'dst_ig', None)

        # Camada IP (L3)
        if hasattr(packet, 'ip'):
            src_ip = getattr(packet.ip, 'src', None)
            dst_ip = getattr(packet.ip, 'dst', None)
            proto_ip = getattr(packet.ip, 'proto', None)
            ttl_ip = getattr(packet.ip, 'ttl', None)
            flags_ip = getattr(packet.ip, 'flags', None)
            len_ip = getattr(packet.ip, 'len', None)
            checksum_ip = getattr(packet.ip, 'checksum', None)

        # Camada TCP (L4)
        if hasattr(packet, 'tcp'):
            srcport_tcp = getattr(packet.tcp, 'srcport', None)
            dstport_tcp = getattr(packet.tcp, 'dstport', None)
            flags_tcp = getattr(packet.tcp, 'flags', None)
            seq_tcp = getattr(packet.tcp, 'seq', None)
            ack_tcp = getattr(packet.tcp, 'ack', None)
            window_size_tcp = getattr(packet.tcp, 'window_size', None)
            len_tcp = getattr(packet.tcp, 'len', None)
            tcp_time_delta = getattr(packet.tcp, 'time_delta', None)  # Tempo entre pacotes TCP
            tcp_retransmission = getattr(packet.tcp, 'analysis_retransmission', None)  # Retransmissões anormais

        # Camada UDP (L4)
        if hasattr(packet, 'udp'):
            srcport_udp = getattr(packet.udp, 'srcport', None)
            dstport_udp = getattr(packet.udp, 'dstport', None)
            length_udp = getattr(packet.udp, 'length', None)
            checksum_udp = getattr(packet.udp, 'checksum', None)

        # Camada DNS (L7)
        if hasattr(packet, 'dns'):
            dns_qry_name = getattr(packet.dns, 'qry_name', None)
            dns_qry_type = getattr(packet.dns, 'qry_type', None)
            dns_a = getattr(packet.dns, 'a', None)
            dns_aaaa = getattr(packet.dns, 'aaaa', None)
            dns_resp_name = getattr(packet.dns, 'resp_name', None)
            dns_flags_response = getattr(packet.dns, 'flags_response', None)

        # Camada HTTP/HTTPS (L7)
        if hasattr(packet, 'http'):
            http_request_method = getattr(packet.http, 'request_method', None)
            http_host = getattr(packet.http, 'host', None)
            http_request_uri = getattr(packet.http, 'request_uri', None)
            http_user_agent = getattr(packet.http, 'user_agent', None)
            http_response_code = getattr(packet.http, 'response_code', None)

        # Camada TLS/SSL (L7)
        if hasattr(packet, 'tls'):
            tls_record_version = getattr(packet.tls, 'record_version', None)
            tls_handshake_type = getattr(packet.tls, 'handshake_type', None)
            tls_sni = getattr(packet.tls, 'handshake_extensions_server_name', None)

        # Camada ARP (L2)
        if hasattr(packet, 'arp'):
            arp_src_ip = getattr(packet.arp, 'src_proto_ipv4', None)
            arp_dst_ip = getattr(packet.arp, 'dst_proto_ipv4', None)
            arp_src_mac = getattr(packet.arp, 'src_hw_mac', None)
            arp_dst_mac = getattr(packet.arp, 'dst_hw_mac', None)
            arp_opcode = getattr(packet.arp, 'opcode', None)

        # Camada DHCP (L7)
        if hasattr(packet, 'dhcp'):
            dhcp_message_type = getattr(packet.dhcp, 'option_dhcp', None)
            dhcp_hostname = getattr(packet.dhcp, 'option_hostname', None)
            dhcp_requested_ip = getattr(packet.dhcp, 'option_requested_ip', None)

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