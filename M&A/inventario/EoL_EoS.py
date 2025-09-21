
# aqui com geração da planilha

import pandas as pd
from datetime import datetime
import os

def verificar_equipamentos_eos():
    print("\n=== Verificação de Equipamentos Fora de Suporte (EoL/EoS) ===")

    # Procurar arquivos de inventário
    arquivos = [f for f in os.listdir() if f.endswith(".xlsx") or f.endswith(".csv")]
    if not arquivos:
        print("❌ Nenhum arquivo de inventário encontrado na pasta.")
        return

    # Exibir lista de inventários disponíveis
    print("\n📁 Inventários encontrados:")
    for i, arquivo in enumerate(arquivos, 1):
        print(f"{i}. {arquivo}")

    try:
        escolha = int(input("\nDigite o número do inventário desejado: "))
        arquivo_inventario = arquivos[escolha - 1]
    except:
        print("❌ Escolha inválida.")
        return

    # Carregar o inventário
    print(f"\n📄 Lendo inventário: {arquivo_inventario}")
    if arquivo_inventario.endswith(".csv"):
        inventario = pd.read_csv(arquivo_inventario)
    else:
        inventario = pd.read_excel(arquivo_inventario)

    if 'Modelo' not in inventario.columns:
        print("❌ O inventário precisa conter uma coluna chamada 'Modelo'.")
        return

    # Verificar se a base eos_database.csv existe
    base_path = "eos_database.csv"
    if not os.path.exists(base_path):
        print(f"❌ Base de referência '{base_path}' não encontrada.")
        return

    eos_db = pd.read_csv(base_path)

    if 'Modelo' not in eos_db.columns or 'EoS' not in eos_db.columns:
        print("❌ A base eos_database.csv precisa conter colunas: Modelo, EoL, EoS.")
        return

    # Padronizar texto para comparação
    inventario['Modelo'] = inventario['Modelo'].str.upper().str.strip()
    eos_db['Modelo'] = eos_db['Modelo'].str.upper().str.strip()

    # Converter datas
    # eos_db['EoS'] = pd.to_datetime(eos_db['EoS'], errors='coerce')
    # eos_db['EoL'] = pd.to_datetime(eos_db['EoL'], errors='coerce')
    eos_db['EoS'] = pd.to_datetime(eos_db['EoS'], dayfirst=True, errors='coerce')
    eos_db['EoL'] = pd.to_datetime(eos_db['EoL'], dayfirst=True, errors='coerce')

    # Mesclar dados
    resultado = pd.merge(inventario, eos_db, on='Modelo', how='left')

    # Avaliar status
    hoje = datetime.today()
    resultado['Status'] = resultado['EoS'].apply(
        lambda data: '❌ Fora de Suporte' if pd.notnull(data) and data < hoje else '✅ Suportado'
    )
    resultado['Recomendação'] = resultado['Status'].apply(
        lambda status: '⚠️ Substituir/Planejar upgrade' if 'Fora' in status else 'OK'
    )

    # Nome do arquivo de saída
    nome_saida = "equipamentos_eos_resultado.xlsx"
    resultado.to_excel(nome_saida, index=False)

    print(f"\n✅ Análise finalizada. Resultado salvo em: {nome_saida}")

if __name__ == "__main__":
    verificar_equipamentos_eos()