from scapy.all import *
import ipaddress

# Caminho do arquivo .pcapng
arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_IPspoofing.pcapng"

# Lista de ranges de IPs privados
ranges_privados = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def ip_privado(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    return any(ip_obj in rede for rede in ranges_privados)

# Carregar pacotes do arquivo
pkts = rdpcap(arquivo_pcap)

# Verificar pacotes com IP de origem privado
print("\n🔎 Pacotes com IP de origem privado (spoofing suspeito):\n")
for pkt in pkts:
    if IP in pkt:
        ip_origem = pkt[IP].src
        if ip_privado(ip_origem):
            print(f"Possível spoofing → IP de origem: {ip_origem} → Destino: {pkt[IP].dst}")

# Explicação
# O script lê o .pcapng.
#
# Filtra todos os pacotes com protocolo IP.
#
# Verifica se o IP de origem é de uma faixa privada.
#
# Se for, imprime como possível spoofing, pois IPs privados não deveriam estar chegando de fora da rede local.
