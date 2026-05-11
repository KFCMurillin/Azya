import os
import time
from db import conectar_banco, submenu_urls
from scanner import menu_cybersecurity
from utils import limpar_tela, carregando, mostrar_resultados
from banner import mostrar_banner_simples, centralizar_texto, animar_banner_cima_para_baixo

def menu(cursor, conn):
    opcoes = [
        "Gerenciar URLs",
        "CyberSecurity",
        "Resultados dos Testes",
        "Sair"
    ]
    while True:
        limpar_tela()
        mostrar_banner_simples()
        print()
        print(centralizar_texto("Menu da Azya:"))
        print()
        try:
            colunas = os.get_terminal_size().columns
        except OSError:
            colunas = 80
        pontos_total = max(40, colunas // 2)
        for idx, opcao in enumerate(opcoes, 1):
            pontos = '.' * (pontos_total - len(opcao) - len(str(idx)))
            linha = f"{opcao}{pontos}{idx}"
            print(centralizar_texto(linha))
        print()
        escolha = input("Selecione uma opção: ").strip()
        if escolha == "1":
            carregando("Entrando")
            submenu_urls(cursor, conn)
        elif escolha == "2":
            carregando("Entrando")
            menu_cybersecurity(cursor)
        elif escolha == "3":
            mostrar_resultados()
        elif escolha == "4" or escolha == "0":
            carregando("Saindo")
            print(centralizar_texto("Saindo"))
            break
        else:
            print(centralizar_texto("Opção inválida. Tente novamente."))
            time.sleep(1)

if __name__ == "__main__":
    try:
        from banner import animar_banner_cima_para_baixo
        animar_banner_cima_para_baixo(delay=0.25)
        time.sleep(5)
    except ImportError:
        pass
    conn, cursor = conectar_banco()
    try:
        menu(cursor, conn)
    finally:
        conn.close()
