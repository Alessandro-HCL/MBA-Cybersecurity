import pyshark
import csv


# aqui abrindo o arquivo do wireshark
capture = pyshark.FileCapture(
    r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura.pcapng"
)

# Cria/abre um arquivo CSV para escrita
with open('packets.csv', 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)

    # Escreve o cabeçalho (colunas)
    writer.writerow(['src_eth', 'dst_eth', 'type_eth', 'oui_eth_src', 'oui_eth_dst','lg_eth','ig_eth', 'src_ip', 'dst_ip','proto_ip', 'ttl_ip', 'flags_ip','len_ip', 'checksum_ip', 'srcport_tcp', 'dstport_tcp', 'flags_tcp', 'seq_tcp','ack_tcp', 'window_size_tcp','len_tcp'])
    for packet in capture:
        if hasattr(packet, 'ip'):# Uma forma simples de evitar o erro é verificar se a camada IP existe antes de tentar acessá-la. Assim, se o pacote não tiver IPv4, o Python não chamará packet.ip.
            #Camada de Enlace (Ethernet - L2) - Ajuda a identificar dispositivos suspeitos, endereços MAC falsificados (MAC Spoofing) e ataques ARP spoofing.
            src_eth = packet.eth.src
            dst_eth = packet.eth.dst
            type_eth = packet.eth.type #Tipo do protocolo na camada superior (ex.: IPv4 = 0x0800, IPv6 = 0x86dd, ARP = 0x0806)
            oui_eth_src = packet.eth.src_oui_resolved #Fabricante da placa de rede
            oui_eth_dst = packet.eth.dst_oui_resolved #Fabricante da placa de rede
            lg_eth = packet.eth.dst_lg #Indica se o MAC de destino é localmente administrado
            ig_eth = packet.eth.dst_ig # Indica se o MAC de destino é multicast
            src_ip = packet.ip.src#Endereço IP de origem
            dst_ip = packet.ip.dst#Endereço IP de destino
            proto_ip = packet.ip.proto#Protocolo da camada de transporte (ex.: TCP = 6, UDP = 17, ICMP = 1)
            ttl_ip = packet.ip.ttl
            flags_ip = packet.ip.flags#Flags de fragmentação
            len_ip = packet.ip.len#Tamanho total do pacote
            checksum_ip = packet.ip.checksum#Checksum do cabeçalho IP
            srcport_tcp = packet.tcp.srcport
            dstport_tcp = packet.tcp.dstport
            flags_tcp = packet.tcp.flags
            seq_tcp = packet.tcp.seq
            ack_tcp = packet.tcp.ack
            window_size_tcp = packet.tcp.window_size
            len_tcp = packet.tcp.len




        # Escreve a linha no CSV
        writer.writerow([src_eth, dst_eth, type_eth, oui_eth_src, oui_eth_dst, lg_eth, ig_eth, src_ip, dst_ip, proto_ip, ttl_ip, flags_ip, len_ip, checksum_ip, srcport_tcp, dstport_tcp, flags_tcp, seq_tcp, ack_tcp, window_size_tcp, len_tcp])






