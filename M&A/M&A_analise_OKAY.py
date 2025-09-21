from datetime import datetime
import pandas as pd
import subprocess
import os
import sys


def listar_inventarios():
    pasta = "inventario"
    if not os.path.exists(pasta):
        print("📂 Pasta 'inventario' não encontrada.")
        return []

    arquivos = [f for f in os.listdir(pasta) if f.endswith(".xlsx")]
    if not arquivos:
        print("⚠️ Nenhum inventário encontrado na pasta.")
        return []

    print("\n📁 Inventários disponíveis:")
    for i, arquivo in enumerate(arquivos):
        print(f"{i + 1}. {arquivo}")
    return arquivos

def inventario_rede():
    arquivos = listar_inventarios()
    if not arquivos:
        return

    try:
        escolha = int(input("\nDigite o número do inventário que deseja abrir: "))
        if escolha < 1 or escolha > len(arquivos):
            print("❌ Escolha inválida.")
            return
        caminho = os.path.join("inventario", arquivos[escolha - 1])
        df = pd.read_excel(caminho)

        colunas_principais = [
            "IP", "Cisco_Hostname", "Modelo", "Serial", "IOS",
            "Uptime", "Portas Abertas", "Uso de CPU (%)", "Uso de Memória (%)"
        ]
        colunas_validas = [col for col in colunas_principais if col in df.columns]
        print(f"\n📊 Inventário: {arquivos[escolha - 1]}")
        print(df[colunas_validas].to_string(index=False))
    except Exception as e:
        print(f"❌ Erro ao carregar o inventário: {e}")



def identificar_riscos_operacionais():
    arquivos = listar_inventarios()
    if not arquivos:
        return

    try:
        escolha = int(input("\nDigite o número do inventário que deseja analisar: "))
        if escolha < 1 or escolha > len(arquivos):
            print("❌ Escolha inválida.")
            return

        caminho = os.path.join("inventario", arquivos[escolha - 1])
        df = pd.read_excel(caminho)

        # Inicializar a coluna de risco como OK
        df['Risco'] = 'OK'

        # Verificar e aplicar cada condição de risco se a coluna existir
        if 'Uso de CPU (%)' in df.columns:
            df['Uso de CPU (%)'] = pd.to_numeric(df['Uso de CPU (%)'], errors='coerce')
            df.loc[df['Uso de CPU (%)'] > 80, 'Risco'] = 'ALTO'
        else:
            print("⚠️ Coluna 'Uso de CPU (%)' não encontrada. Ignorando esse critério.")

        if 'Uso de Memória (%)' in df.columns:
            df['Uso de Memória (%)'] = pd.to_numeric(df['Uso de Memória (%)'], errors='coerce')
            df.loc[df['Uso de Memória (%)'] > 80, 'Risco'] = 'ALTO'
        else:
            print("⚠️ Coluna 'Uso de Memória (%)' não encontrada. Ignorando esse critério.")

        if 'Uptime' in df.columns:
            df['UptimeDias'] = df['Uptime'].str.extract(r'(\d+)').astype(float)
            df['UptimeDias'] = df['UptimeDias'].fillna(0)
            df.loc[df['UptimeDias'] > 365, 'Risco'] = 'ALTO'
        else:
            print("⚠️ Coluna 'Uptime' não encontrada. Ignorando esse critério.")

        # Filtrar e mostrar apenas os dispositivos com risco alto
        resultados = df[df["Risco"] == "ALTO"]
        if resultados.empty:
            print("\n✅ Nenhum risco operacional alto detectado.")
        else:
            colunas = [col for col in [
                "IP", "Cisco_Hostname", "Modelo", "Uso de CPU (%)",
                "Uso de Memória (%)", "Uptime", "Risco"
            ] if col in df.columns]
            print(f"\n⚠️ Equipamentos com RISCO OPERACIONAL ALTO:")
            print(resultados[colunas].to_string(index=False))

    except Exception as e:
        print(f"❌ Erro durante análise de riscos: {e}")






def verificar_equipamentos_eos():
    print("\n=== Verificação de Equipamentos Fora de Suporte (EoL/EoS) ===")

    # Caminho da pasta de inventários
    pasta_inventario = "inventario"

    # Verificar se a pasta existe
    if not os.path.exists(pasta_inventario):
        print("❌ Pasta de inventário não encontrada.")
        return

    # Listar arquivos .xlsx e .csv
    arquivos = [f for f in os.listdir(pasta_inventario) if f.endswith(".xlsx") or f.endswith(".csv")]
    if not arquivos:
        print("❌ Nenhum arquivo de inventário encontrado na pasta.")
        return

    print("\n📁 Inventários encontrados:")
    for i, arquivo in enumerate(arquivos, 1):
        print(f"{i}. {arquivo}")

    try:
        escolha = int(input("\nDigite o número do inventário desejado: "))
        if escolha < 1 or escolha > len(arquivos):
            print("❌ Escolha inválida.")
            return
        arquivo_inventario = os.path.join(pasta_inventario, arquivos[escolha - 1])
    except:
        print("❌ Entrada inválida.")
        return

    print(f"\n📄 Lendo inventário: {arquivo_inventario}")
    if arquivo_inventario.endswith(".csv"):
        inventario = pd.read_csv(arquivo_inventario)
    else:
        inventario = pd.read_excel(arquivo_inventario)

    if 'Modelo' not in inventario.columns:
        print("❌ O inventário precisa conter uma coluna chamada 'Modelo'.")
        return

    # Caminho da base EoL/EoS
    base_path = os.path.join(pasta_inventario, "eos_database.csv")
    if not os.path.exists(base_path):
        print(f"❌ Base de referência '{base_path}' não encontrada.")
        return

    eos_db = pd.read_csv(base_path)

    if 'Modelo' not in eos_db.columns or 'EoS' not in eos_db.columns or 'EoL' not in eos_db.columns:
        print("❌ A base eos_database.csv precisa conter colunas: Modelo, EoL, EoS.")
        return

    # Padronizar modelos
    inventario['Modelo'] = inventario['Modelo'].str.upper().str.strip()
    eos_db['Modelo'] = eos_db['Modelo'].str.upper().str.strip()

    # Converter datas
    eos_db['EoS'] = pd.to_datetime(eos_db['EoS'], dayfirst=True, errors='coerce')
    eos_db['EoL'] = pd.to_datetime(eos_db['EoL'], dayfirst=True, errors='coerce')

    # Mesclar os dados
    resultado = pd.merge(inventario, eos_db, on='Modelo', how='left')

    # Avaliar status
    hoje = datetime.today()
    resultado['Status'] = resultado['EoS'].apply(
        lambda data: '❌ Fora de Suporte' if pd.notnull(data) and data < hoje else '✅ Suportado'
    )
    resultado['Recomendação'] = resultado['Status'].apply(
        lambda status: '⚠️ Substituir/Planejar upgrade' if 'Fora' in status else 'OK'
    )

    # Salvar resultado final
    nome_saida = os.path.join(pasta_inventario, "equipamentos_eos_resultado.xlsx")
    resultado.to_excel(nome_saida, index=False)

    print(f"\n✅ Análise finalizada. Resultado salvo em: {nome_saida}")

def submenu_MA():
    while True:
        print("\n=== MÓDULO 4️⃣ – Análise de M&A ===")
        print("1 Inventário completo da rede")
        print("2 Identificação de riscos operacionais")
        print("3 Equipamentos suporte - Status (EoL/EoS)")
        print("4 Estimativa de CAPEX para atualização - Desenvolvendo")
        print("5 Exportar relatório executivo (Excel) - Desenvolvendo")
        print("0️⃣ Voltar ao menu principal")

        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            # print("🔍 Executando: Inventário completo da rede...")
            inventario_rede()
        elif opcao == "2":
            # print("⚠️ Executando: Identificação de riscos operacionais...")
            identificar_riscos_operacionais()
        elif opcao == "3":
            # print("📛 Executando: Equipamentos sem suporte (EoL/EoS)...")
            verificar_equipamentos_eos()

        elif opcao == "4":
            print("💰 Executando: Estimativa de CAPEX para atualização...")
        elif opcao == "5":
            print("📁 Executando: Exportar relatório executivo...")
        elif opcao == "0":
            print("🔙 Retornando ao menu principal...")
            break
        else:
            print("❌ Opção inválida. Tente novamente.")



if __name__ == "__main__":
    submenu_MA()