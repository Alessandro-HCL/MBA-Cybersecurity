
import subprocess
import os
import sys


def menu_principal():
    while True:
        print("\n\U0001F4E1 MENU PRINCIPAL")
        print("1️⃣ Coleta de Dados da Rede")
        print("2️⃣ Simulação de Ataques Ativos (Red Team)")
        print("3️⃣ Simulação de Detecção Passiva (Blue Team)")
        print("4️⃣ Módulo de Análise de M&A")
        print("0️⃣ Sair")

        opcao = input("\n👉 Escolha uma opção: ").strip()

        if opcao == "1":
            print("\n🔍 Iniciando coleta de dados da rede...")
            executar_script("Coleta_dados-OKAY.py")

        elif opcao == "2":
            # print("\n\uD83D\uDDE1\uFE0F Iniciando simulação Red Team...")
            print("\n🔍 Iniciando simulação Red Team...")
            executar_script("Red_team_ataque_OKAY.py")

        elif opcao == "3":
            # print("\n\uD83D\uDEE1\uFE0F Iniciando simulação Blue Team...")
            print("\n🔍 Iniciando simulação Blue Team...")
            executar_script("Blue_team_detecção_OKAY.py")

        elif opcao == "4":
            print("\n\U0001F4CA Executando módulo de análise de M&A...")
            executar_script("M&A_analise_OKAY.py")

        elif opcao == "0":
            print("\nSaindo...")
            break

        else:
            print("\nOpção inválida. Tente novamente.")


def executar_script(nome_arquivo):
    caminho_absoluto = os.path.join(os.path.dirname(__file__), nome_arquivo)
    if os.path.exists(caminho_absoluto):
        try:
            subprocess.run([sys.executable, caminho_absoluto], check=True)
        except subprocess.CalledProcessError as e:
            print(f"\n❌ Erro ao executar o script: {e}")
    else:
        print(f"\n❌ Arquivo {nome_arquivo} não encontrado na pasta atual.")




if __name__ == "__main__":
    menu_principal()

