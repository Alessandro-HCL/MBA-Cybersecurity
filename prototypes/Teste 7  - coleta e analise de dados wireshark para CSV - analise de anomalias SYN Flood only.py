from scapy.all import *

# Caminho para o arquivo coletado no Wireshark
arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_SYNFlood.pcapng"

print("🔍 Carregando pacotes...")
#aqui estava demorando muito para carregar devido ao tamenho do arquivo, daí limitei aos 10 mil primeiros pacotes
# pkts = rdpcap(arquivo)
pkts = rdpcap(arquivo, count=10000)

print("🔎 Analisando pacotes SYN (sem ACK)...")
syn_count = {}
ack_count = {}

for pkt in pkts:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip_src = pkt[IP].src
        tcp_flags = pkt[TCP].flags

        if tcp_flags == 'S':  # Apenas SYN
            syn_count[ip_src] = syn_count.get(ip_src, 0) + 1

        elif 'A' in tcp_flags and 'S' not in tcp_flags:  # Apenas ACK
            ack_count[ip_src] = ack_count.get(ip_src, 0) + 1

# Verificar se algum IP enviou muitas SYNs mas poucos ACKs
print("\n🔐 Resultado da análise:")
ataque_detectado = False
for ip in syn_count:
    syns = syn_count[ip]
    acks = ack_count.get(ip, 0)
    ratio = acks / syns if syns > 0 else 0

    if syns > 100 and ratio < 0.1:  # Muitos SYNs, pouquíssimos ACKs
        print(f"⚠️ Possível SYN Flood detectado do IP {ip} ({syns} SYNs, {acks} ACKs, taxa ACK/SYN = {ratio:.2f})")
        ataque_detectado = True

if not ataque_detectado:
    print("✅ Nenhum SYN Flood detectado.")
