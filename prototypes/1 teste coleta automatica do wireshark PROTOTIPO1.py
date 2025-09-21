
# Versão 1 - sem ataque
#==================================================
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scp import SCPClient
# from scapy.all import rdpcap, IP
#
# # 1. Iniciar captura tshark na máquina host (ajuste a interface correta)
# print("🎥 Iniciando captura com tshark...")
# tshark_proc = subprocess.Popen([
#     # "tshark", "-i", "Wi-Fi", "-w", "captura_IPspoofing.pcapng"
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
# ])
#
# # 2. Conectar via SSH na VM Kali e executar ataque spoofing
# print("💥 Conectando via SSH na VM Kali para iniciar o ataque...")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname="192.168.198.130", username="alessandro", password="npfnm1msv")
#
# # Comando para rodar script de ataque (ex: hping3)
# stdin, stdout, stderr = ssh.exec_command("sudo python3 /home/kali/ataque_spoofing.py")
# stdout.channel.recv_exit_status()
# print(stdout.read().decode())
#
# # Aguarda alguns segundos para garantir que o tráfego foi capturado
# time.sleep(10)
#
# # 3. Finalizar captura
# print("🛑 Encerrando captura tshark...")
# tshark_proc.terminate()
# time.sleep(3)
#
# # 4. Transferir arquivo pcapng da máquina local para pasta do script
# print("📂 Transferindo arquivo de captura...")
# # (Neste caso já está local; se capturasse na VM, usaria SCP para puxar)
#
# # 5. Rodar a análise dos pacotes
# print("🔎 Analisando captura...")
#
# arquivo_pcap = "captura_IPspoofing.pcapng"
# # arquivo_pcap = "captura.pcapng"
#
# ranges_privados = [
#     ipaddress.ip_network("10.0.0.0/8"),
#     ipaddress.ip_network("172.16.0.0/12"),
#     ipaddress.ip_network("192.168.0.0/16"),
# ]
#
# # Lista de IPs da sua rede que você quer ignorar na análise
# ips_confiaveis = {
#     "192.168.1.5",  # Seu PC host
# }
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     return any(ip_obj in rede for rede in ranges_privados)
#
# pkts = rdpcap(arquivo_pcap)
#
# print("\n🔎 Pacotes com IP de origem privado (spoofing suspeito):\n")
# for pkt in pkts:
#     if IP in pkt:
#         ip_origem = pkt[IP].src
#         # if ip_privado(ip_origem):
#         #     print(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#         if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#             print(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")


# Versão 2 - aqui inclui o ataque de forma automatica via python - FUNCIONANDO
# PROXIMO PASSO: tentar fazer um menu para o tipo de ataque, selecionar a opção e daí cair por exemplo nesta opção de ip spoofing
#===================================================================================================================================

import subprocess
import time
import paramiko
import ipaddress
from scapy.all import rdpcap, IP

# 👉 Entrada dos IPs
ip_kali = input("🖥️  IP da máquina Kali: ").strip()
ip_spoofado = input("🎭 IP que será usado como spoof (falso): ").strip()
ip_vitima = input("🎯 IP da máquina alvo (vítima): ").strip()

# 1. Iniciar captura tshark na máquina host (ajuste a interface correta)
print("\n🎥 Iniciando captura com tshark...\n")
tshark_proc = subprocess.Popen([
    r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
])

# 2. Conectar via SSH na VM Kali e executar ataque spoofing com hping3
print(f"💥 Conectando via SSH na VM Kali ({ip_kali}) para iniciar o ataque...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")

print(f"🚀 Disparando spoofing: {ip_spoofado} → {ip_vitima} (porta 80)...")
# comando_ataque = f"sudo hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
comando_ataque = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"

# stdin, stdout, stderr = ssh.exec_command(comando_ataque)
# stdout.channel.recv_exit_status()
# print(stdout.read().decode())
# print(stderr.read().decode())
stdin, stdout, stderr = ssh.exec_command(comando_ataque)
output = stdout.read().decode()
errors = stderr.read().decode()
print(output)
print(errors)

# Aguarda alguns segundos para garantir captura
time.sleep(20)

# 3. Finalizar captura
print("🛑 Encerrando captura tshark...")
tshark_proc.terminate()
time.sleep(3)

# 4. Analisar o arquivo capturado
print("📂 Transferindo arquivo de captura...")
arquivo_pcap = "captura_IPspoofing.pcapng"

# 5. Rodar a análise dos pacotes
print("🔎 Analisando captura...\n")

ranges_privados = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# IPs confiáveis
ips_confiaveis = {
    "192.168.1.12", "192.168.1.13", "192.168.1.6", # Exemplo: sua máquina física
    ip_spoofado,    # Opcional: ignora o spoofador para focar em terceiros
}
# ips_confiaveis = {
#     "192.168.1.4",
#     "192.168.1.5",
#     "192.168.1.6",
#     "192.168.1.9",  # Kali
#     "192.168.1.11", # Vítima
# }

def ip_privado(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    return any(ip_obj in rede for rede in ranges_privados)

# Carrega pacotes
pkts = rdpcap(arquivo_pcap)

# Filtra e mostra suspeitas
print("\n🔎 Pacotes com IP de origem privado (spoofing suspeito):\n")
for pkt in pkts:
    if IP in pkt:
        ip_origem = pkt[IP].src
        # if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
        #     print(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
        if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
            print(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
        # elif not ip_privado(ip_origem) and ip_privado(pkt[IP].dst):
        #     print(f"⚠️ Possível spoof externo: {ip_origem} → {pkt[IP].dst}")
