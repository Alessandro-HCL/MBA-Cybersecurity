import pyshark
from collections import defaultdict

# Caminho do arquivo capturado no Wireshark
arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_TLS4.pcapng"


print("🔍 Analisando TLS Client Hello sem resposta...")

# Lista de conexões com Client Hello
client_hellos = set()

# Lista de conexões com Server Hello
server_hellos = set()

# Carrega somente pacotes de handshake TLS
cap = pyshark.FileCapture(
    arquivo_pcap,
    display_filter="tls.handshake",
    keep_packets=False
)

for pkt in cap:
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt.tcp.srcport
        dst_port = pkt.tcp.dstport
        tls_type = int(pkt.tls.handshake_type)

        conn = (src_ip, src_port, dst_ip, dst_port)

        if tls_type == 1:  # Client Hello
            client_hellos.add(conn)

        elif tls_type == 2:  # Server Hello
            # inverso do Client Hello (resposta)
            conn_response = (dst_ip, dst_port, src_ip, src_port)
            server_hellos.add(conn_response)

    except AttributeError:
        continue

cap.close()

# Conexões que iniciaram handshake mas não receberam resposta
ataques = client_hellos - server_hellos

print("\n🔐 Resultado da análise:")
if ataques:
    for conn in ataques:
        print(f"⚠️ Handshake incompleto de {conn[0]}:{conn[1]} → {conn[2]}:{conn[3]}")
    print(f"\n⚠️ Total de anomalias detectadas: {len(ataques)}")
else:
    print("✅ Nenhuma anomalia TLS detectada.")

print("✅ Análise concluída.")
