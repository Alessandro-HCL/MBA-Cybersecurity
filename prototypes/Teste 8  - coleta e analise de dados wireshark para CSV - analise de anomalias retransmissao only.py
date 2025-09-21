# import pyshark
# from collections import defaultdict
#
# # Caminho para o arquivo de captura
# arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_retrans.pcapng"
#
#
# print("🔍 Carregando captura e analisando retransmissões TCP...")
#
# # Carrega apenas pacotes TCP com campo de retransmissão identificado
# captura = pyshark.FileCapture(
#     arquivo_pcap,
#     display_filter="tcp.analysis.retransmission",
#     keep_packets=False
# )
#
# # Contador de retransmissões por IP de origem
# retransmissao_por_ip = defaultdict(int)
#
# for pkt in captura:
#     try:
#         ip_src = pkt.ip.src
#         retransmissao_por_ip[ip_src] += 1
#     except AttributeError:
#         continue
#
# captura.close()
#
# # Avalia se houve ataque
# print("\n🔐 Resultado da análise:")
# ataque_detectado = False
# for ip, count in retransmissao_por_ip.items():
#     if count > 20:  # Limiar configurável (ajuste conforme o cenário)
#         print(f"⚠️ Retransmissões TCP anormais detectadas do IP {ip} ({count} retransmissões).")
#         ataque_detectado = True
#
# if not ataque_detectado:
#     print("✅ Nenhuma retransmissão TCP anormal detectada.")
#
# print("✅ Análise concluída.")

from scapy.all import *
from collections import defaultdict

arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_retrans2.pcapng"

pkts = rdpcap(arquivo)

print("🔍 Analisando retransmissões TCP manualmente...")

# Dicionário para armazenar (IP origem, destino, seq_num) → contagem
seqs = defaultdict(int)
retransmissoes = defaultdict(int)

for pkt in pkts:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq
        key = (ip_src, ip_dst, sport, dport, seq)

        seqs[key] += 1
        if seqs[key] > 1:
            retransmissoes[ip_src] += 1

# Resultados
print("\n🔐 Resultado da análise:")
ataque_detectado = False
for ip, count in retransmissoes.items():
    if count > 10:
        print(f"⚠️ Retransmissões detectadas do IP {ip} ({count} pacotes repetidos).")
        ataque_detectado = True

if not ataque_detectado:
    print("✅ Nenhuma retransmissão anormal detectada.")

print("✅ Análise concluída.")
