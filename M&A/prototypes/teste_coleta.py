# AQUI FUNCIONOU PARA HOSTNAME

# import paramiko
# import re
#
# # 🔧 Configurações
# ip = "192.168.198.51"
# username = "admin"
# password = "cisco12345"
#
# def coletar_hostname(ip, username, password):
#     print(f"🔐 Conectando em {ip} via SSH...")
#     try:
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(ip, username=username, password=password, timeout=5)
#
#         stdin, stdout, stderr = ssh.exec_command("show version")
#         saida = stdout.read().decode()
#         ssh.close()
#
#         # 🧠 Extrair hostname da saída: busca por 'hostname uptime is'
#         match = re.search(r"(\S+)\s+uptime is", saida)
#         if match:
#             hostname = match.group(1)
#             print(f"\n✅ Hostname identificado: {hostname}")
#         else:
#             print("⚠️ Hostname não encontrado na saída do comando.")
#
#     except Exception as e:
#         print(f"❌ Falha no acesso SSH: {e}")
#
# # ▶️ Execução
# coletar_hostname(ip, username, password)



# AQUI FUNCIONANDO PARA OUTROS PARAMENTROS E COLADO SAIDA NO CHAT

# import paramiko
# import re
#
# # Configuração do dispositivo Cisco
# ip = "192.168.198.51"
# username = "admin"
# password = "cisco12345"
#
# def coletar_info_show_version(ip, username, password):
#     print(f"🔐 Conectando em {ip} via SSH...")
#     try:
#         # Inicializa sessão SSH
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(ip, username=username, password=password, timeout=5)
#
#         # Executa o comando
#         stdin, stdout, stderr = ssh.exec_command("show version")
#         saida = stdout.read().decode()
#         ssh.close()
#
#         # 🧠 Expressões regulares para extrair os dados
#         hostname = re.search(r"(\S+)\s+uptime is", saida)
#         serial = re.search(r"Processor board ID (\S+)", saida)
#         modelo = re.search(r"Cisco (\S+) .*bytes of memory", saida)
#         ios = re.search(r"Cisco IOS Software, .* Version ([^,]+),", saida)
#         uptime = re.search(r"uptime is (.*)", saida)
#
#         print("\n🧾 Resultado da Coleta:")
#         print(f"Hostname       : {hostname.group(1) if hostname else 'Não encontrado'}")
#         print(f"Serial Number  : {serial.group(1) if serial else 'Não encontrado'}")
#         print(f"Modelo         : {modelo.group(1) if modelo else 'Não encontrado'}")
#         print(f"IOS Version    : {ios.group(1) if ios else 'Não encontrado'}")
#         print(f"Uptime         : {uptime.group(1) if uptime else 'Não encontrado'}")
#
#     except Exception as e:
#         print(f"❌ Erro na conexão ou coleta: {e}")
#
# # ▶️ Execução
# coletar_info_show_version(ip, username, password)


# AQUI FUNCIONANDO PARA OUTRAS SAIDA DO SH VER

# import paramiko
# import pandas as pd
# import re
# from datetime import datetime
#
# # Configurações do equipamento Cisco
# ip = "192.168.198.51"
# usuario = "admin"
# senha = "cisco12345"
#
# # Função para coletar o show version via SSH
# def coletar_info_cisco(ip, usuario, senha):
#     print(f"🔐 Conectando ao dispositivo {ip}...")
#
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)
#
#     stdin, stdout, stderr = ssh.exec_command("show version")
#     saida = stdout.read().decode()
#     ssh.close()
#
#     # Extração de dados via regex
#     hostname = re.search(r'(\S+) uptime is', saida)
#     serial = re.search(r'Processor board ID (\S+)', saida)
#     modelo = re.search(r'^Cisco\s+(\S+)', saida, re.M)
#     ios = re.search(r'Cisco IOS Software,.*Version ([^\s,]+)', saida)
#     uptime = re.search(r'uptime is ([^\n]+)', saida)
#
#     return {
#         "IP": ip,
#         "Hostname": hostname.group(1) if hostname else "Desconhecido",
#         "Serial": serial.group(1) if serial else "Desconhecido",
#         "Modelo": modelo.group(1) if modelo else "Desconhecido",
#         "IOS": ios.group(1) if ios else "Desconhecido",
#         "Uptime": uptime.group(1).strip() if uptime else "Desconhecido"
#     }
#
# # Coleta
# dados = coletar_info_cisco(ip, usuario, senha)
#
# # Criação da planilha
# df = pd.DataFrame([dados])
# agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
# nome_arquivo = f"inventario_cisco_{agora}.xlsx"
# df.to_excel(nome_arquivo, index=False)
#
# print(f"\n✅ Planilha salva como: {nome_arquivo}")


# import paramiko
# import pandas as pd
# import re
# from datetime import datetime
#
# # Configurações do equipamento Cisco
# ip = "192.168.198.51"
# usuario = "admin"
# senha = "cisco12345"
#
# # Função para coletar o show version via SSH
# def coletar_info_cisco(ip, usuario, senha):
#     print(f"🔐 Conectando ao dispositivo {ip}...")
#
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)
#
#     stdin, stdout, stderr = ssh.exec_command("show version")
#     saida = stdout.read().decode()
#     ssh.close()
#
#     # Extração de dados via regex
#     hostname = re.search(r'(\S+) uptime is', saida)
#     serial = re.search(r'Processor board ID (\S+)', saida)
#     modelo = re.search(r'^Cisco\s+(\S+)', saida, re.M)
#     ios = re.search(r'Cisco IOS Software,.*Version ([^\s,]+)', saida)
#     uptime = re.search(r'uptime is ([^\n]+)', saida)
#
#     return {
#         "IP": ip,
#         "Hostname": hostname.group(1) if hostname else "Desconhecido",
#         "Serial": serial.group(1) if serial else "Desconhecido",
#         "Modelo": modelo.group(1) if modelo else "Desconhecido",
#         "IOS": ios.group(1) if ios else "Desconhecido",
#         "Uptime": uptime.group(1).strip() if uptime else "Desconhecido"
#     }
#
# # Coleta
# dados = coletar_info_cisco(ip, usuario, senha)
#
# # Criação da planilha
# df = pd.DataFrame([dados])
# agora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
# nome_arquivo = f"inventario_cisco_{agora}.xlsx"
# df.to_excel(nome_arquivo, index=False)
#
# print(f"\n✅ Planilha salva como: {nome_arquivo}")


# AQUI INCLUINDO OUTROS COMANDOS ALEM DO SH VER

# import paramiko
# import re
# import time
#
# ip = "192.168.198.51"
# usuario = "admin"
# senha = "cisco12345"
#
# print(f"🔐 Conectando ao dispositivo {ip}...")
#
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)
#
# shell = ssh.invoke_shell()
# shell.settimeout(2)
#
# # Enviar comandos
# shell.send("terminal length 0\n")
# time.sleep(1)
#
# shell.send("show version\n")
# time.sleep(2)
# saida_version = shell.recv(9999).decode(errors="ignore")
#
# shell.send("show ip interface brief\n")
# time.sleep(2)
# saida_intbrief = shell.recv(9999).decode(errors="ignore")
#
# ssh.close()
#
# # Debug
# print("\n📄 Saída do show version:")
# print("-" * 50)
# print(saida_version)
#
# print("\n📄 Saída do show ip interface brief:")
# print("-" * 50)
# print(saida_intbrief)
#
# # Regex para extração
# hostname = re.search(r'(\S+)\s+uptime is', saida_version)
# serial = re.search(r'Processor board ID (\S+)', saida_version)
# modelo = re.search(r'Cisco IOS Software, (\S+)', saida_version)
# ios = re.search(r'Version ([\d\.\(\)A-Z]+)', saida_version)
# uptime = re.search(r'uptime is ([^\n]+)', saida_version)
#
# # Interfaces up/up
# interfaces_ativas = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s+up\s+up', saida_intbrief, re.M)
# qtd_interfaces_ativas = len(interfaces_ativas)
#
# # Mostrar dados extraídos
# print("\n📊 Dados extraídos:")
# print("-" * 50)
# print(f"Hostname: {hostname.group(1) if hostname else 'Desconhecido'}")
# print(f"Serial: {serial.group(1) if serial else 'Desconhecido'}")
# print(f"Modelo: {modelo.group(1) if modelo else 'Desconhecido'}")
# print(f"IOS: {ios.group(1) if ios else 'Desconhecido'}")
# print(f"Uptime: {uptime.group(1).strip() if uptime else 'Desconhecido'}")
# print(f"Interfaces Ativas (up/up): {qtd_interfaces_ativas}")


# FUNCIONANDO

# import paramiko
# import re
# import time
#
# # Configurações do equipamento
# ip = "192.168.198.51"
# usuario = "admin"
# senha = "cisco12345"
#
# print(f"🔐 Conectando ao dispositivo {ip}...")
#
# # Conexão SSH
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)
#
# shell = ssh.invoke_shell()
# shell.settimeout(2)
#
# def enviar_comando(comando, espera=2):
#     shell.send(comando + "\n")
#     time.sleep(espera)
#     return shell.recv(9999).decode(errors="ignore")
#
# # Envio dos comandos
# # saida_mem = enviar_comando("sh memory summary | i Processor")
# # saida_mem = enviar_comando("sh memory summary")
#
# shell.send("terminal length 0\n")
# time.sleep(1)
# saida_mem = enviar_comando("sh memory summary | i Processor")
# saida_version = enviar_comando("show version")
# saida_intbrief = enviar_comando("show ip interface brief")
# saida_cpu = enviar_comando("show processes cpu")
#
# print("\n📄 DEBUG: Saída completa do sh memory summary:")
# print("-" * 60)
# print(saida_mem)
# print("-" * 60)
#
# ssh.close()
#
# # 🧠 Extração show version
# hostname = re.search(r'(\S+)\s+uptime is', saida_version)
# serial = re.search(r'Processor board ID (\S+)', saida_version)
# modelo = re.search(r'Cisco IOS Software, (\S+)', saida_version)
# ios = re.search(r'Version ([\d\.\(\)A-Z]+)', saida_version)
# uptime = re.search(r'uptime is ([^\n]+)', saida_version)
#
# # Extração interfaces up/up
# interfaces_ativas = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s+up\s+up', saida_intbrief, re.M)
# qtd_interfaces_ativas = len(interfaces_ativas)
#
# # Extração CPU
# cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', saida_cpu)
# cpu_percent = cpu_match.group(1) if cpu_match else "Desconhecido"
#
# # ✅ Extração Memória com fallback
# mem_match = re.search(r'^Processor\s+\S+\s+(\d+)\s+(\d+)', saida_mem, re.M)
# if not mem_match:
#     mem_match = re.search(r'^Processor\s+\S*\s+(\d{6,})\s+(\d{6,})', saida_mem, re.M)
#
# if mem_match:
#     total = int(mem_match.group(1))
#     used = int(mem_match.group(2))
#     mem_percent = f"{(used / total) * 100:.1f}"
# else:
#     mem_percent = "Desconhecido"
#
# # 📊 Exibir no terminal
# print("\n📊 INFORMAÇÕES DO DISPOSITIVO")
# print("-" * 60)
# print(f"IP....................: {ip}")
# print(f"Hostname..............: {hostname.group(1) if hostname else 'Desconhecido'}")
# print(f"Serial................: {serial.group(1) if serial else 'Desconhecido'}")
# print(f"Modelo................: {modelo.group(1) if modelo else 'Desconhecido'}")
# print(f"IOS...................: {ios.group(1) if ios else 'Desconhecido'}")
# print(f"Uptime................: {uptime.group(1).strip() if uptime else 'Desconhecido'}")
# print(f"Interfaces Ativas.....: {qtd_interfaces_ativas}")
# print(f"Uso de CPU (%)........: {cpu_percent}")
# print(f"Uso de Memória (%)....: {mem_percent}")
# print("-" * 60)


# FUNCIONANDO - VARIOS COMANDOS E SAIDAS (AQUI AINDA SEM PLANILHA)

# PESQUISADOS
#
# Dispositivo IP	IP detectado via ARP/Nmap
# Hostname	Nome do equipamento extraído do show version
# Modelo	Modelo do switch ou roteador (ex: C9300, vios_l2, etc.)
# Serial	Identificador único do hardware (asset tracking)
# IOS / Versão	Versão do sistema operacional Cisco
# Uptime	Tempo ligado desde último boot
# CPU (%)	Média da CPU dos últimos 5 segundos (show proc cpu)
# Memória (%)	Percentual da memória usada
# Portas Ativas	Contagem de interfaces up/up
# VLANs	VLANs configuradas no dispositivo (show vlan brief)
# CDP Vizinhos	Lista dos vizinhos físicos detectados (show cdp neighbors)
# Erro de Interface	Total de erros de entrada/CRC nas portas (show interfaces counters)
# Módulos	Detalhamento dos módulos, transceivers e placas (show inventory)
# MAC Ativos	Quantidade de endereços MAC aprendidos (show mac address-table)
#
#
# PENDENTES
# Roteador?	Se o equipamento tem funções de roteamento (sim/não)
# Rotas Ativas	Número de rotas configuradas (show ip route)
# Temperatura	Resultado do show environment
# Fonte Redundante	Se há mais de uma fonte de energia funcionando corretamente
# Usuários Locais	Usuários configurados no running-config

# import paramiko
# import re
# import time
#
# # Configurações do equipamento
# ip = "192.168.198.51"
# usuario = "admin"
# senha = "cisco12345"
#
# print(f"🔐 Conectando ao dispositivo {ip}...")
#
# # Conexão SSH
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)
#
# shell = ssh.invoke_shell()
# shell.settimeout(2)
#
# def enviar_comando(comando, espera=2):
#     shell.send(comando + "\n")
#     time.sleep(espera)
#     return shell.recv(9999).decode(errors="ignore")
#
# # Envio dos comandos
#
# shell.send("terminal length 0\n")
# time.sleep(1)
# saida_vlans = enviar_comando("show vlan brief")
# saida_cdp = enviar_comando("show cdp neighbors")
# saida_erros = enviar_comando("show interfaces counters errors")
# saida_mac = enviar_comando("show mac address-table")
# # 🔍 Coleta de módulos, transceivers e placas
# saida_inventory = enviar_comando("show inventory")
# # saida_temp = enviar_comando("show environment")
# saida_mem = enviar_comando("sh memory summary | i Processor")
# saida_version = enviar_comando("show version")
# saida_intbrief = enviar_comando("show ip interface brief")
# saida_cpu = enviar_comando("show processes cpu")
# # saida_vlans = enviar_comando("show vlan brief")
#
#
#
#
# print("\n📄 DEBUG: Saída completa do show mac address-table:")
# print("-" * 60)
# print(saida_mac)
# print("-" * 60)
#
# ssh.close()
#
# # 🧠 Extração show version
# hostname = re.search(r'(\S+)\s+uptime is', saida_version)
# serial = re.search(r'Processor board ID (\S+)', saida_version)
# modelo = re.search(r'Cisco IOS Software, (\S+)', saida_version)
# ios = re.search(r'Version ([\d\.\(\)A-Z]+)', saida_version)
# uptime = re.search(r'uptime is ([^\n]+)', saida_version)
#
# # Extração interfaces up/up
# interfaces_ativas = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s+up\s+up', saida_intbrief, re.M)
# qtd_interfaces_ativas = len(interfaces_ativas)
#
# # Extração CPU
# cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', saida_cpu)
# cpu_percent = cpu_match.group(1) if cpu_match else "Desconhecido"
#
# # ✅ Extração Memória com fallback
# mem_match = re.search(r'^Processor\s+\S+\s+(\d+)\s+(\d+)', saida_mem, re.M)
# if not mem_match:
#     mem_match = re.search(r'^Processor\s+\S*\s+(\d{6,})\s+(\d{6,})', saida_mem, re.M)
#
# if mem_match:
#     total = int(mem_match.group(1))
#     used = int(mem_match.group(2))
#     mem_percent = f"{(used / total) * 100:.1f}"
# else:
#     mem_percent = "Desconhecido"
#
# # Extração de VLANs
# vlans = re.findall(r'^(\d+)\s+[\w-]+\s+active', saida_vlans, re.M)
# vlans_ativas = ", ".join(vlans) if vlans else "Nenhuma"
#
#
# # Extração de vizinhos CDP
# cdp_vizinhos = re.findall(r'^(\S+)\s+\n\s+Gig \d+/\d+', saida_cdp, re.M)
# qtd_vizinhos = len(cdp_vizinhos)
# vizinhos_cdp = ", ".join(cdp_vizinhos) if qtd_vizinhos else "Nenhum"
#
# # Extração dos erros de entrada por interface
# erros_entrada = re.findall(r'^(\S+)\s+\d+\s+(\d+)\s+(\d+)', saida_erros, re.M)
# erros_totais = 0
# erros_por_porta = []
#
# for porta, input_err, crc in erros_entrada:
#     total_erros = int(input_err) + int(crc)
#     if total_erros > 0:
#         erros_por_porta.append(f"{porta} ({total_erros} erros)")
#         erros_totais += total_erros
#
# if erros_por_porta:
#     resumo_erros = f"{erros_totais} erros em: " + ", ".join(erros_por_porta)
# else:
#     resumo_erros = "Nenhum erro detectado"
#
#
# # 📦 Extração de informações de módulos (primeiro bloco como exemplo)
# modulos = re.findall(r'NAME: "([^"]+)", DESCR: "([^"]+)"\s+PID: (\S+),.*SN: (\S+)', saida_inventory)
#
# if modulos:
#     modulos_info = "\n".join([f"{nome} ({descr}) - PID: {pid}, SN: {sn}" for nome, descr, pid, sn in modulos])
# else:
#     if "not supported" in saida_inventory.lower() or "invalid input" in saida_inventory.lower():
#         modulos_info = "Não suportado neste equipamento"
#     else:
#         modulos_info = "Nenhum módulo encontrado"
#
#
# # 🧠 Contar entradas dinâmicas (endereços MAC aprendidos)
# macs_dinamicos = re.findall(r'DYNAMIC\s+(\S+)', saida_mac)
# qtd_mac_ativos = len(macs_dinamicos)
#
# # 📊 Exibir no terminal
# print("\n📊 INFORMAÇÕES DO DISPOSITIVO")
# print("-" * 60)
# print(f"IP....................: {ip}")
# print(f"Hostname..............: {hostname.group(1) if hostname else 'Desconhecido'}")
# print(f"Serial................: {serial.group(1) if serial else 'Desconhecido'}")
# print(f"Modelo................: {modelo.group(1) if modelo else 'Desconhecido'}")
# print(f"IOS...................: {ios.group(1) if ios else 'Desconhecido'}")
# print(f"Uptime................: {uptime.group(1).strip() if uptime else 'Desconhecido'}")
# print(f"Interfaces Ativas.....: {qtd_interfaces_ativas}")
# print(f"VLANs Ativas..........: {vlans_ativas}")
# print(f"CDP Vizinhos..........: {cdp_vizinhos}")
# print(f"Erros de Interface.....: {resumo_erros}")
# print(f"Módulos................: {modulos_info.splitlines()[0] if ' - PID:' in modulos_info else modulos_info}")
# print(f"MACs Ativos............: {qtd_mac_ativos}")
# # print(f"Temperatura............: {temperatura}")
# print(f"Uso de CPU (%)........: {cpu_percent}")
# print(f"Uso de Memória (%)....: {mem_percent}")
# print("-" * 60)



# AQUI FUNCIONANDO COM VARIAS SAIDAS E GERANDO PLANILHA

import paramiko
import re
import time
import pandas as pd
from datetime import datetime
import os

# Configurações do equipamento
ip = "192.168.198.51"
usuario = "admin"
senha = "cisco12345"

print(f"🔐 Conectando ao dispositivo {ip}...")

# Conexão SSH
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(ip, username=usuario, password=senha, look_for_keys=False, allow_agent=False)

shell = ssh.invoke_shell()
shell.settimeout(2)

def enviar_comando(comando, espera=2):
    shell.send(comando + "\n")
    time.sleep(espera)
    return shell.recv(9999).decode(errors="ignore")

# Envio dos comandos

shell.send("terminal length 0\n")
time.sleep(1)
saida_vlans = enviar_comando("show vlan brief")
saida_cdp = enviar_comando("show cdp neighbors")
saida_erros = enviar_comando("show interfaces counters errors")
saida_mac = enviar_comando("show mac address-table")
# 🔍 Coleta de módulos, transceivers e placas
saida_inventory = enviar_comando("show inventory")
# saida_temp = enviar_comando("show environment")
saida_mem = enviar_comando("sh memory summary | i Processor")
saida_version = enviar_comando("show version")
saida_intbrief = enviar_comando("show ip interface brief")
saida_cpu = enviar_comando("show processes cpu")
# saida_vlans = enviar_comando("show vlan brief")




print("\n📄 DEBUG: Saída completa do show mac address-table:")
print("-" * 60)
print(saida_mac)
print("-" * 60)

ssh.close()

# 🧠 Extração show version
hostname = re.search(r'(\S+)\s+uptime is', saida_version)
serial = re.search(r'Processor board ID (\S+)', saida_version)
modelo = re.search(r'Cisco IOS Software, (\S+)', saida_version)
ios = re.search(r'Version ([\d\.\(\)A-Z]+)', saida_version)
uptime = re.search(r'uptime is ([^\n]+)', saida_version)

# Extração interfaces up/up
interfaces_ativas = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s+up\s+up', saida_intbrief, re.M)
qtd_interfaces_ativas = len(interfaces_ativas)

# Extração CPU
cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', saida_cpu)
cpu_percent = cpu_match.group(1) if cpu_match else "Desconhecido"

# ✅ Extração Memória com fallback
mem_match = re.search(r'^Processor\s+\S+\s+(\d+)\s+(\d+)', saida_mem, re.M)
if not mem_match:
    mem_match = re.search(r'^Processor\s+\S*\s+(\d{6,})\s+(\d{6,})', saida_mem, re.M)

if mem_match:
    total = int(mem_match.group(1))
    used = int(mem_match.group(2))
    mem_percent = f"{(used / total) * 100:.1f}"
else:
    mem_percent = "Desconhecido"

# Extração de VLANs
vlans = re.findall(r'^(\d+)\s+[\w-]+\s+active', saida_vlans, re.M)
vlans_ativas = ", ".join(vlans) if vlans else "Nenhuma"


# Extração de vizinhos CDP
cdp_vizinhos = re.findall(r'^(\S+)\s+\n\s+Gig \d+/\d+', saida_cdp, re.M)
qtd_vizinhos = len(cdp_vizinhos)
vizinhos_cdp = ", ".join(cdp_vizinhos) if qtd_vizinhos else "Nenhum"

# Extração dos erros de entrada por interface
erros_entrada = re.findall(r'^(\S+)\s+\d+\s+(\d+)\s+(\d+)', saida_erros, re.M)
erros_totais = 0
erros_por_porta = []

for porta, input_err, crc in erros_entrada:
    total_erros = int(input_err) + int(crc)
    if total_erros > 0:
        erros_por_porta.append(f"{porta} ({total_erros} erros)")
        erros_totais += total_erros

if erros_por_porta:
    resumo_erros = f"{erros_totais} erros em: " + ", ".join(erros_por_porta)
else:
    resumo_erros = "Nenhum erro detectado"


# 📦 Extração de informações de módulos (primeiro bloco como exemplo)
modulos = re.findall(r'NAME: "([^"]+)", DESCR: "([^"]+)"\s+PID: (\S+),.*SN: (\S+)', saida_inventory)

if modulos:
    modulos_info = "\n".join([f"{nome} ({descr}) - PID: {pid}, SN: {sn}" for nome, descr, pid, sn in modulos])
else:
    if "not supported" in saida_inventory.lower() or "invalid input" in saida_inventory.lower():
        modulos_info = "Não suportado neste equipamento"
    else:
        modulos_info = "Nenhum módulo encontrado"


# 🧠 Contar entradas dinâmicas (endereços MAC aprendidos)
macs_dinamicos = re.findall(r'DYNAMIC\s+(\S+)', saida_mac)
qtd_mac_ativos = len(macs_dinamicos)

# 📊 Exibir no terminal
print("\n📊 INFORMAÇÕES DO DISPOSITIVO")
print("-" * 60)
print(f"IP....................: {ip}")
print(f"Hostname..............: {hostname.group(1) if hostname else 'Desconhecido'}")
print(f"Serial................: {serial.group(1) if serial else 'Desconhecido'}")
print(f"Modelo................: {modelo.group(1) if modelo else 'Desconhecido'}")
print(f"IOS...................: {ios.group(1) if ios else 'Desconhecido'}")
print(f"Uptime................: {uptime.group(1).strip() if uptime else 'Desconhecido'}")
print(f"Interfaces Ativas.....: {qtd_interfaces_ativas}")
print(f"VLANs Ativas..........: {vlans_ativas}")
print(f"CDP Vizinhos..........: {cdp_vizinhos}")
print(f"Erros de Interface.....: {resumo_erros}")
print(f"Módulos................: {modulos_info.splitlines()[0] if ' - PID:' in modulos_info else modulos_info}")
print(f"MACs Ativos............: {qtd_mac_ativos}")
# print(f"Temperatura............: {temperatura}")
print(f"Uso de CPU (%)........: {cpu_percent}")
print(f"Uso de Memória (%)....: {mem_percent}")
print("-" * 60)

# Substitua esses dados pelas variáveis extraídas no seu script
dados = {
    "IP": ip,
    "Hostname": hostname.group(1) if hostname else 'Desconhecido',
    "Serial": serial.group(1) if serial else 'Desconhecido',
    "Modelo": modelo.group(1) if modelo else 'Desconhecido',
    "IOS": ios.group(1) if ios else 'Desconhecido',
    "Uptime": uptime.group(1).strip() if uptime else 'Desconhecido',
    "Interfaces Ativas": qtd_interfaces_ativas,
    "VLANs Ativas": vlans_ativas,
    "CDP Vizinhos": vizinhos_cdp,
    "Erros de Interface": resumo_erros,
    "Módulos": modulos_info.splitlines()[0] if ' - PID:' in modulos_info else modulos_info,
    "MACs Ativos": qtd_mac_ativos,
    "Uso de CPU (%)": cpu_percent,
    "Uso de Memória (%)": mem_percent
}

# Criar DataFrame
df = pd.DataFrame([dados])

# Gerar nome do arquivo com timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
nome_arquivo = f"relatorio_dispositivo_{dados['Hostname']}_{timestamp}.xlsx"
df.to_excel(nome_arquivo, index=False)
