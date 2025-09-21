# import pyshark
# # from collections import defaultdict
# # from scapy.all import *
# #
# # # Caminho do arquivo .pcapng capturado com Wireshark
# # arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_TCPSYNScan2.pcapng"
# #
# #
# # print("🔍 Testando parsing básico com only_summaries...")
# #
# # cap = pyshark.FileCapture(
# #     arquivo_pcap,
# #     only_summaries=True,
# #     keep_packets=False
# # )
# #
# # for i, pkt in enumerate(cap):
# #     print(pkt)
# #     if i >= 10:
# #         break
# #
# # cap.close()


from scapy.all import *

# Caminho do arquivo pcapng
arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_TCPSYNScan2.pcapng"
# arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_MACspoofing.pcapng"
# arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_SYNFlood.pcapng"


print("🔍 Carregando pacotes...")
# pkts = rdpcap(arquivo)
pkts = rdpcap(arquivo, count=10000)

print("🔎 Analisando pacotes TCP SYN...")
syn_por_ip = {}

for pkt in pkts:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[TCP].flags == 'S':
            ip_src = pkt[IP].src
            dst_port = pkt[TCP].dport
            syn_por_ip.setdefault(ip_src, set()).add(dst_port)

print("\n🔐 Resultado da análise:")
ataque_detectado = False
for ip, portas in syn_por_ip.items():
    if len(portas) > 30:
        print(f"⚠️ Escaneamento de portas detectado do IP {ip} ({len(portas)} portas diferentes).")
        ataque_detectado = True

if not ataque_detectado:
    print("✅ Nenhum escaneamento de portas detectado.")