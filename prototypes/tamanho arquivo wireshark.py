from scapy.all import *

arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_UDPFlood.pcapng"
# arquivo = arquivo_pcap =r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_MACspoofing.pcapng"


# pkts = rdpcap(arquivo)
pkts = rdpcap(arquivo, count=10000)

print(f"🔢 Total de pacotes: {len(pkts)}")
