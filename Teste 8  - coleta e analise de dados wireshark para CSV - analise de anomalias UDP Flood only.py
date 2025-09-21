from scapy.all import *

arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_UDPFlood3.pcapng"
# arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_MACspoofing.pcapng"

pkts = rdpcap(arquivo, count=10000)

print("🔎 Analisando pacotes UDP...")
udp_count = {}

for pkt in pkts:
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        ip_src = pkt[IP].src
        udp_count[ip_src] = udp_count.get(ip_src, 0) + 1

print("\n🔐 Resultado da análise:")
ataque_detectado = False
for ip, count in udp_count.items():
    if count > 500:  # Threshold para detectar flood
        print(f"⚠️ Possível UDP Flood detectado do IP {ip} ({count} pacotes UDP enviados).")
        ataque_detectado = True

if not ataque_detectado:
    print("✅ Nenhum UDP Flood detectado.")