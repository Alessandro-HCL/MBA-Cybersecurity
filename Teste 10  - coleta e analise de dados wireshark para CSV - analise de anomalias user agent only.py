import pyshark

# Caminho do arquivo capturado no Wireshark
arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_agent.pcapng"
# arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_dominio.pcapng"


# Whitelist básica de User-Agents legítimos (você pode expandir)
user_agents_validos = [
    "mozilla", "chrome", "safari", "edge", "firefox", "opera", "msie"
]

print("🔍 Iniciando análise de User-Agents suspeitos...\n")

# Carrega somente pacotes HTTP
cap = pyshark.FileCapture(
    arquivo_pcap,
    display_filter="http.request",
    keep_packets=False
)

user_agents_suspeitos = set()

for pkt in cap:
    try:
        if hasattr(pkt.http, 'user_agent'):
            user_agent = pkt.http.user_agent.lower()
            if not any(ua in user_agent for ua in user_agents_validos):
                print(f"⚠️ User-Agent suspeito detectado: {user_agent}")
                user_agents_suspeitos.add(user_agent)
    except AttributeError:
        continue

cap.close()

# Resultado
if user_agents_suspeitos:
    print(f"\n🔐 Total de User-Agents suspeitos encontrados: {len(user_agents_suspeitos)}")
else:
    print("✅ Nenhum User-Agent suspeito detectado.")