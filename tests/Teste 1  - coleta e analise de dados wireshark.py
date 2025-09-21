import pyshark

# aqui abrindo o arquivo do wireshark
capture = pyshark.FileCapture(
    r"D:\Alessandro\Documentos\Particular\Certificações_profissional\_Reciclagem - Volta ao mercado de trabalho\analise com wireshark\Cyber Security testes\captura2.pcapng"
)

# for packet in capture:
# #     print(packet.frame.number)# aqui listando todo o conteudo do arquivo
#
#     if hasattr(packet, 'eth'):
#     # O EtherType geralmente está em 'packet.eth.type'
#         ethertype = packet.eth.type
#         print("EtherType:", ethertype)

# print(packet.eth.field_names) #Você pode listar todos os campos de uma camada em PyShark para descobrir nomes exatos
# print(packet.eth)# ou inspecionar o conteúdo diretamente


# for packet in capture:
#     print(packet.ip.src, packet.ip.dst, packet.length)

# for packet in capture:
#     print(packet.udp.srcport)

for packet in capture:
    if hasattr(packet, 'tls') and hasattr(packet, 'ip'):
    # print(packet.ip.field_names)#aqui mostrando os campos dentro de eth
        print(packet.tls)

# for packet in capture:
#     if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
#         # Primeiro, verifica se o campo 'flags' existe na camada TCP
#         tcp_flags = getattr(packet.tcp, 'flags', None)

        # if tcp_flags:  # Se o campo de flags existir, acessa os valores individuais
        #     syn_flag = getattr(packet.tcp, 'flags_syn', None)
        #     ack_flag = getattr(packet.tcp, 'flags_ack', None)
        #     fin_flag = getattr(packet.tcp, 'flags_fin', None)
        #     rst_flag = getattr(packet.tcp, 'flags_rst', None)
        #     # Apenas para depuração (remova ou comente esta linha caso não queira imprimir)
        #     print(f"SYN: {syn_flag}, ACK: {ack_flag}, FIN: {fin_flag}, RST: {rst_flag}")
        #     print(packet.tcp.flags.syn)
