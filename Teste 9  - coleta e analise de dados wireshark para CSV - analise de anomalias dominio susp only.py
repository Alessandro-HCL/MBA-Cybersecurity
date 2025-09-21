import pyshark

# Caminho do arquivo .pcapng capturado
arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_dominio.pcapng"
# arquivo = arquivo_pcap = r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura_retrans2.pcapng"


# TLDs considerados suspeitos (pode personalizar)
tlds_suspeitos = ['.ru', '.tk', '.xyz', '.top', '.cn', '.gq', '.ml', '.ga']

print("🔍 Iniciando análise de domínios suspeitos...")

# Carrega pacotes com DNS ou HTTP
cap = pyshark.FileCapture(
    arquivo,
    display_filter="dns || http",
    keep_packets=False
)

dominios_detectados = []

for pkt in cap:
    try:
        # DNS
        if hasattr(pkt, 'dns'):
            if hasattr(pkt.dns, 'qry_name'):
                dominio = pkt.dns.qry_name.lower()
                if any(tld in dominio for tld in tlds_suspeitos):
                    print(f"⚠️ [DNS] Domínio suspeito detectado: {dominio}")
                    dominios_detectados.append(dominio)

        # HTTP
        if hasattr(pkt, 'http'):
            if hasattr(pkt.http, 'host'):
                host = pkt.http.host.lower()
                if any(tld in host for tld in tlds_suspeitos):
                    print(f"⚠️ [HTTP] Host suspeito detectado: {host}")
                    dominios_detectados.append(host)

    except AttributeError:
        continue

cap.close()

if not dominios_detectados:
    print("✅ Nenhuma comunicação com domínios suspeitos detectada.")
else:
    print(f"\n✅ Total: {len(set(dominios_detectados))} domínios suspeitos identificados.")