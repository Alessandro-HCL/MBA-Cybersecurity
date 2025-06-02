import streamlit as st
import subprocess
import os

# Função para executar scripts
def executar_script(script_nome):
    caminho_completo = os.path.join(os.getcwd(), script_nome)
    resultado = subprocess.run(["python", caminho_completo], capture_output=True, text=True)
    st.text_area("📄 Saída do Script:", resultado.stdout + "\n" + resultado.stderr, height=300)

# Título
st.title("🔐 Plataforma de Cibersegurança e Análise de M&A")

# Menu principal
opcao = st.sidebar.selectbox(
    "Selecione uma opção:",
    ["Selecione...", "Coleta de Dados da Rede", "Simulação de Ataques Ativos (Red Team)",
     "Simulação de Detecção Passiva (Blue Team)", "Módulo de Análise de M&A"]
)

# Execução conforme a escolha
if opcao == "Coleta de Dados da Rede":
    st.subheader("🔍 Iniciando coleta de dados da rede...")
    executar_script("Coleta_dados-OKAY.py")

elif opcao == "Simulação de Ataques Ativos (Red Team)":
    st.subheader("🛡️ Iniciando simulação Red Team...")
    executar_script("Red_team_ataque_OKAY.py")

elif opcao == "Simulação de Detecção Passiva (Blue Team)":
    st.subheader("🔎 Iniciando simulação Blue Team...")
    executar_script("Blue_team_detecção_OKAY.py")

elif opcao == "Módulo de Análise de M&A":
    st.subheader("📊 Executando módulo de análise de M&A...")
    executar_script("M&A_analise_OKAY.py")

else:
    st.info("Selecione uma opção no menu lateral para iniciar.")
