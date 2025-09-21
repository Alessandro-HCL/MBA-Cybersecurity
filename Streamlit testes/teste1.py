# import streamlit as st
# import pandas as pd
# import os
# from datetime import datetime
# import subprocess
# import sys
#
# # Função auxiliar para executar scripts externos
# def executar_script(nome_arquivo):
#     caminho_absoluto = os.path.join(os.path.dirname(__file__), nome_arquivo)
#     if os.path.exists(caminho_absoluto):
#         try:
#             subprocess.run([sys.executable, caminho_absoluto], check=True)
#         except subprocess.CalledProcessError as e:
#             st.error(f"Erro ao executar o script: {e}")
#     else:
#         st.error(f"Arquivo {nome_arquivo} não encontrado na pasta atual.")
#
# # Funções de análise
#
# def listar_inventarios():
#     pasta = "inventario"
#     if not os.path.exists(pasta):
#         return []
#     return [f for f in os.listdir(pasta) if f.endswith(".xlsx") or f.endswith(".csv")]
#
# def inventario_rede(arquivo):
#     caminho = os.path.join("inventario", arquivo)
#     df = pd.read_excel(caminho)
#     colunas_principais = [
#         "IP", "Cisco_Hostname", "Modelo", "Serial", "IOS",
#         "Uptime", "Portas Abertas", "Uso de CPU (%)", "Uso de Memória (%)"
#     ]
#     colunas_validas = [col for col in colunas_principais if col in df.columns]
#     st.subheader(f"Inventário: {arquivo}")
#     st.dataframe(df[colunas_validas])
#
# def identificar_riscos_operacionais(arquivo):
#     caminho = os.path.join("inventario", arquivo)
#     df = pd.read_excel(caminho)
#     df['Risco'] = 'OK'
#
#     if 'Uso de CPU (%)' in df.columns:
#         df['Uso de CPU (%)'] = pd.to_numeric(df['Uso de CPU (%)'], errors='coerce')
#         df.loc[df['Uso de CPU (%)'] > 80, 'Risco'] = 'ALTO'
#
#     if 'Uso de Memória (%)' in df.columns:
#         df['Uso de Memória (%)'] = pd.to_numeric(df['Uso de Memória (%)'], errors='coerce')
#         df.loc[df['Uso de Memória (%)'] > 80, 'Risco'] = 'ALTO'
#
#     if 'Uptime' in df.columns:
#         df['UptimeDias'] = df['Uptime'].str.extract(r'(\d+)').astype(float).fillna(0)
#         df.loc[df['UptimeDias'] > 365, 'Risco'] = 'ALTO'
#
#     resultados = df[df["Risco"] == "ALTO"]
#     st.subheader("Equipamentos com RISCO OPERACIONAL ALTO")
#     if resultados.empty:
#         st.success("Nenhum risco operacional alto detectado.")
#     else:
#         colunas = [col for col in ["IP", "Cisco_Hostname", "Modelo", "Uso de CPU (%)",
#                                    "Uso de Memória (%)", "Uptime", "Risco"] if col in df.columns]
#         st.dataframe(resultados[colunas])
#
# def verificar_equipamentos_eos(arquivo):
#     caminho = os.path.join("inventario", arquivo)
#     base_path = os.path.join("inventario", "eos_database.csv")
#     if not os.path.exists(base_path):
#         st.error("Base de referência eos_database.csv não encontrada.")
#         return
#
#     inventario = pd.read_excel(caminho) if arquivo.endswith(".xlsx") else pd.read_csv(caminho)
#     eos_db = pd.read_csv(base_path)
#
#     inventario['Modelo'] = inventario['Modelo'].str.upper().str.strip()
#     eos_db['Modelo'] = eos_db['Modelo'].str.upper().str.strip()
#
#     eos_db['EoS'] = pd.to_datetime(eos_db['EoS'], dayfirst=True, errors='coerce')
#     eos_db['EoL'] = pd.to_datetime(eos_db['EoL'], dayfirst=True, errors='coerce')
#
#     resultado = pd.merge(inventario, eos_db, on='Modelo', how='left')
#     hoje = datetime.today()
#     resultado['Status'] = resultado['EoS'].apply(
#         lambda data: '❌ Fora de Suporte' if pd.notnull(data) and data < hoje else '✅ Suportado'
#     )
#     resultado['Recomendação'] = resultado['Status'].apply(
#         lambda status: '⚠️ Substituir/Planejar upgrade' if 'Fora' in status else 'OK'
#     )
#
#     st.subheader("Resultado EoL/EoS")
#     st.dataframe(resultado)
#
# # Streamlit App
# st.set_page_config(page_title="Plataforma de Cibersegurança", layout="wide")
# st.title("🔐 Plataforma de Análise de Rede e Cibersegurança")
#
# menu = st.sidebar.radio("Escolha uma opção:", [
#     "🏗️ Coleta de Dados da Rede",
#     "🛡️ Simulação de Ataques Ativos (Red Team)",
#     "🔍 Simulação de Detecção Passiva (Blue Team)",
#     "📊 Análise de M&A"
# ])
#
# if menu == "🏗️ Coleta de Dados da Rede":
#     if st.button("Executar coleta de dados"):
#         executar_script("Coleta_dados-OKAY.py")
#
# elif menu == "🛡️ Simulação de Ataques Ativos (Red Team)":
#     if st.button("Executar Red Team"):
#         executar_script("Red_team_ataque_OKAY.py")
#
# elif menu == "🔍 Simulação de Detecção Passiva (Blue Team)":
#     if st.button("Executar Blue Team"):
#         executar_script("Blue_team_detecção_OKAY.py")
#
# elif menu == "📊 Análise de M&A":
#     inventarios = listar_inventarios()
#     if inventarios:
#         escolha = st.selectbox("Selecione um inventário:", inventarios)
#         acao = st.radio("Selecione uma análise:", [
#             "Inventário completo",
#             "Riscos operacionais",
#             "Equipamentos fora de suporte (EoL/EoS)"
#         ])
#
#         if acao == "Inventário completo":
#             inventario_rede(escolha)
#         elif acao == "Riscos operacionais":
#             identificar_riscos_operacionais(escolha)
#         elif acao == "Equipamentos fora de suporte (EoL/EoS)":
#             verificar_equipamentos_eos(escolha)
#     else:
#         st.warning("Nenhum inventário encontrado na pasta 'inventario'.")


import streamlit as st
import paramiko
import pandas as pd
import re
from scapy.all import ARP, Ether, srp
import nmap
import requests
from datetime import datetime
import time
import os
import ipaddress

st.set_page_config(page_title="Coleta de Dados Cisco", layout="wide")
st.title("🔍 Coleta de Dados Cisco")

def buscar_fabricante(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        return "Desconhecido"
    return "Desconhecido"

def escanear_arp(rede_alvo):
    st.info(f"Executando varredura ARP na rede: {rede_alvo}")
    try:
        pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rede_alvo)
        resposta, _ = srp(pacote, timeout=2, verbose=0)
        dispositivos = []
        for _, r in resposta:
            fabricante = buscar_fabricante(r.hwsrc)
            dispositivos.append({"IP": r.psrc, "MAC": r.hwsrc, "Fabricante": fabricante})
        return dispositivos
    except Exception as e:
        st.error(f"Erro na varredura ARP: {e}")
        return []

def escanear_icmp_nmap(rede_alvo):
    st.info(f"Executando fallback ICMP com Nmap na rede: {rede_alvo}")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=rede_alvo, arguments="-sn")
    dispositivos = []
    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', 'Desconhecido')
        fabricante = buscar_fabricante(mac)
        dispositivos.append({"IP": host, "MAC": mac, "Fabricante": fabricante})
    return dispositivos

def enriquecer_com_nmap(dispositivos):
    scanner = nmap.PortScanner()
    for dispositivo in dispositivos:
        ip = dispositivo["IP"]
        st.write(f"🔎 Nmap {ip}")
        try:
            scanner.scan(ip, arguments="-O -T4 --top-ports 10")
            host_data = scanner[ip]
            osmatch = host_data.get("osmatch", [])
            dispositivo["OS"] = osmatch[0]["name"] if osmatch else "Desconhecido"
            portas = []
            if 'tcp' in host_data:
                for porta, info in host_data['tcp'].items():
                    if info['state'] == 'open':
                        portas.append(f"{porta}/{info['name']}")
            dispositivo["Portas Abertas"] = ", ".join(portas) if portas else "Nenhuma"
        except Exception as e:
            dispositivo["OS"] = "Erro"
            dispositivo["Portas Abertas"] = "Erro"
    return dispositivos

def coletar_detalhes_cisco(dispositivo, usuario, senha):
    ip = dispositivo["IP"]
    st.write(f"🔐 Conectando via SSH ao equipamento Cisco {ip}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False, timeout=5)
        shell = ssh.invoke_shell()
        shell.settimeout(10)

        def enviar_comando(cmd, espera=4):
            shell.send(cmd + "\n")
            time.sleep(espera)
            return shell.recv(9999).decode(errors="ignore")

        shell.send("terminal length 0\n")
        time.sleep(1)

        version = enviar_comando("show version")
        vlan = enviar_comando("show vlan brief")
        cdp = enviar_comando("show cdp neighbors")
        erros = enviar_comando("show interfaces counters errors")
        macs = enviar_comando("show mac address-table")
        inventory = enviar_comando("show inventory")
        mem = enviar_comando("sh memory summary | i Processor")
        cpu = enviar_comando("show processes cpu")
        intbrief = enviar_comando("show ip interface brief")

        ssh.close()

        hostname = re.search(r'(\S+) uptime is', version)
        serial = re.search(r'Processor board ID (\S+)', version)
        modelo = re.search(r'Cisco IOS Software, (\S+)', version)
        ios = re.search(r'Version ([\d\.\(\)A-Z]+)', version)
        uptime = re.search(r'uptime is ([^\n]+)', version)

        interfaces_up = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s+up\s+up', intbrief, re.M)
        qtd_interfaces = len(interfaces_up)

        cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', cpu)
        cpu_percent = cpu_match.group(1) if cpu_match else "Desconhecido"

        mem_match = re.search(r'^Processor\s+\S+\s+(\d+)\s+(\d+)', mem, re.M)
        if mem_match:
            total = int(mem_match.group(1))
            used = int(mem_match.group(2))
            mem_percent = f"{(used / total) * 100:.1f}"
        else:
            mem_percent = "Desconhecido"

        vlans = re.findall(r'^(\d+)\s+[\w-]+\s+active', vlan, re.M)
        vlans_ativas = ", ".join(vlans) if vlans else "Nenhuma"

        cdp_vizinhos = re.findall(r'^(\S+)\s+\n\s+Gig \d+/\d+', cdp, re.M)
        vizinhos = ", ".join(cdp_vizinhos) if cdp_vizinhos else "Nenhum"

        erros_entrada = re.findall(r'^(\S+)\s+\d+\s+(\d+)\s+(\d+)', erros, re.M)
        erros_totais = sum(int(e[1]) + int(e[2]) for e in erros_entrada)
        resumo_erros = f"{erros_totais} erro(s)" if erros_totais else "Nenhum erro"

        modulos = re.findall(r'NAME: \"([^\"]+)\", DESCR: \"([^\"]+)\"\s+PID: (\S+),.*SN: (\S+)', inventory)
        modulos_info = modulos[0][0] if modulos else "Nenhum módulo"

        macs_dinamicos = re.findall(r'DYNAMIC\s+(\S+)', macs)
        qtd_mac = len(macs_dinamicos)

        dispositivo.update({
            "Cisco_Hostname": hostname.group(1) if hostname else "Desconhecido",
            "Serial": serial.group(1) if serial else "Desconhecido",
            "Modelo": modelo.group(1) if modelo else "Desconhecido",
            "IOS": ios.group(1) if ios else "Desconhecido",
            "Uptime": uptime.group(1).strip() if uptime else "Desconhecido",
            "Interfaces Ativas": qtd_interfaces,
            "VLANs Ativas": vlans_ativas,
            "CDP Vizinhos": vizinhos,
            "Erros de Interface": resumo_erros,
            "Módulos": modulos_info,
            "MACs Ativos": qtd_mac,
            "Uso de CPU (%)": cpu_percent,
            "Uso de Memória (%)": mem_percent
        })

    except Exception as e:
        dispositivo.update({k: "Erro" for k in [
            "Cisco_Hostname", "Serial", "Modelo", "IOS", "Uptime",
            "Interfaces Ativas", "VLANs Ativas", "CDP Vizinhos",
            "Erros de Interface", "Módulos", "MACs Ativos",
            "Uso de CPU (%)", "Uso de Memória (%)"]})

def salvar_em_excel(dispositivos):
    agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome_arquivo = f"relatorio_cisco_completo_{agora}.xlsx"
    pasta = "inventario"
    os.makedirs(pasta, exist_ok=True)
    caminho_completo = os.path.join(pasta, nome_arquivo)
    df = pd.DataFrame(dispositivos)
    df.to_excel(caminho_completo, index=False)
    st.success(f"✅ Planilha salva como: {caminho_completo}")

def entrada_e_subrede(entrada):
    try:
        ipaddress.IPv4Network(entrada)
        return True
    except:
        return False

st.subheader("Parâmetros da Coleta")
rede_input = st.text_input("Digite a rede ou IP a ser escaneado (ex: 192.168.198.0/24 ou 192.168.198.51):")
usuario_ssh = st.text_input("Usuário SSH", value="admin")
senha_ssh = st.text_input("Senha SSH", type="password")

if st.button("🔍 Iniciar Coleta"):
    if not rede_input:
        st.warning("Por favor, insira a rede ou IP alvo.")
    else:
        todos_dispositivos = []
        if entrada_e_subrede(rede_input):
            dispositivos = escanear_arp(rede_input)
            if not dispositivos:
                dispositivos = escanear_icmp_nmap(rede_input)
        else:
            st.write("🔍 Escaneando IP único...")
            dispositivos = escanear_icmp_nmap(rede_input)

        dispositivos = enriquecer_com_nmap(dispositivos)
        for d in dispositivos:
            if "cisco" in d["OS"].lower() or "ios" in d["OS"].lower():
                coletar_detalhes_cisco(d, usuario_ssh, senha_ssh)
        todos_dispositivos.extend(dispositivos)

        st.write("\n📊 Resultado da Coleta:")
        df_resultado = pd.DataFrame(todos_dispositivos)
        st.dataframe(df_resultado)

        salvar_em_excel(todos_dispositivos)