# M&A_analise_OKAY

import streamlit as st
import pandas as pd
import os
from datetime import datetime

st.set_page_config(page_title="Análise M&A", layout="wide")

pasta_inventario = "inventario"

@st.cache_data
def listar_arquivos():
    if not os.path.exists(pasta_inventario):
        return []
    return [f for f in os.listdir(pasta_inventario) if f.endswith(".xlsx") or f.endswith(".csv")]

def carregar_inventario(nome_arquivo):
    caminho = os.path.join(pasta_inventario, nome_arquivo)
    if nome_arquivo.endswith(".csv"):
        return pd.read_csv(caminho)
    return pd.read_excel(caminho)

st.title("📊 Análise de M&A - Inventário de Rede")

menu = st.sidebar.radio("Escolha uma opção:", [
    "📂 Inventário da Rede",
    "⚠️ Riscos Operacionais",
    "🔒 Equipamentos EoL/EoS"])

arquivos = listar_arquivos()
if not arquivos:
    st.warning("Nenhum inventário encontrado na pasta 'inventario'.")
else:
    nome_arquivo = st.selectbox("Selecione o inventário:", arquivos)
    df = carregar_inventario(nome_arquivo)

    if menu == "📂 Inventário da Rede":
        colunas_exibir = [col for col in [
            "IP", "Cisco_Hostname", "Modelo", "Serial", "IOS",
            "Uptime", "Portas Abertas", "Uso de CPU (%)", "Uso de Memória (%)"
        ] if col in df.columns]
        st.subheader("📊 Inventário da Rede")
        st.dataframe(df[colunas_exibir])

    elif menu == "⚠️ Riscos Operacionais":
        df['Risco'] = 'OK'
        if 'Uso de CPU (%)' in df.columns:
            df['Uso de CPU (%)'] = pd.to_numeric(df['Uso de CPU (%)'], errors='coerce')
            df.loc[df['Uso de CPU (%)'] > 80, 'Risco'] = 'ALTO'
        if 'Uso de Memória (%)' in df.columns:
            df['Uso de Memória (%)'] = pd.to_numeric(df['Uso de Memória (%)'], errors='coerce')
            df.loc[df['Uso de Memória (%)'] > 80, 'Risco'] = 'ALTO'
        if 'Uptime' in df.columns:
            df['UptimeDias'] = df['Uptime'].astype(str).str.extract(r'(\\d+)').astype(float)
            df['UptimeDias'] = df['UptimeDias'].fillna(0)
            df.loc[df['UptimeDias'] > 365, 'Risco'] = 'ALTO'

        risco_df = df[df['Risco'] == 'ALTO']
        if risco_df.empty:
            st.success("Nenhum risco operacional alto detectado.")
        else:
            colunas = [col for col in ["IP", "Cisco_Hostname", "Modelo", "Uso de CPU (%)", "Uso de Memória (%)", "Uptime", "Risco"] if col in risco_df.columns]
            st.subheader("⚠️ Dispositivos com Risco Operacional Alto")
            st.dataframe(risco_df[colunas])

    elif menu == "🔒 Equipamentos EoL/EoS":
        base_path = os.path.join(pasta_inventario, "eos_database.csv")
        if not os.path.exists(base_path):
            st.error("Base 'eos_database.csv' não encontrada na pasta de inventário.")
        else:
            eos_db = pd.read_csv(base_path)
            if not {'Modelo', 'EoL', 'EoS'}.issubset(eos_db.columns):
                st.error("A base 'eos_database.csv' deve conter colunas: Modelo, EoL, EoS.")
            else:
                df['Modelo'] = df['Modelo'].str.upper().str.strip()
                eos_db['Modelo'] = eos_db['Modelo'].str.upper().str.strip()
                eos_db['EoS'] = pd.to_datetime(eos_db['EoS'], dayfirst=True, errors='coerce')
                eos_db['EoL'] = pd.to_datetime(eos_db['EoL'], dayfirst=True, errors='coerce')
                resultado = pd.merge(df, eos_db, on='Modelo', how='left')
                hoje = datetime.today()
                resultado['Status'] = resultado['EoS'].apply(lambda x: '❌ Fora de Suporte' if pd.notnull(x) and x < hoje else '✅ Suportado')
                resultado['Recomendacao'] = resultado['Status'].apply(lambda x: '⚠️ Substituir/Planejar upgrade' if 'Fora' in x else 'OK')
                st.subheader("Equipamentos com Status de Suporte")
                st.dataframe(resultado[["IP", "Modelo", "Status", "Recomendacao"]])

                nome_saida = os.path.join(pasta_inventario, "equipamentos_eos_resultado.xlsx")
                resultado.to_excel(nome_saida, index=False)
                st.success(f"Análise salva em: {nome_saida}")