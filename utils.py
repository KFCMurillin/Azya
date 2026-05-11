import os
import sys
import time

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def carregando(texto="Carregando", tempo=1.5):
    limpar_tela()
    start = time.time()
    while True:
        for i in range(4):
            pontos = '.' * i
            print(f"\r{texto}{pontos}{' ' * (3 - i)}", end='', flush=True)
            time.sleep(0.4)
        if time.time() - start > tempo:
            print()
            return

def salvar_resultado(titulo, conteudo):
    with open("azya_resultados.txt", "a", encoding="utf-8") as f:
        f.write(f"\n{'='*40}\n{titulo}\n{'='*40}\n")
        f.write(conteudo + "\n")

def mostrar_resultados():
    limpar_tela()
    print("RESULTADOS DOS TESTES\n")
    try:
        with open("azya_resultados.txt", "r", encoding="utf-8") as f:
            conteudo = f.read()
        if conteudo.strip():
            print(conteudo)
        else:
            print("Nenhum resultado salvo ainda.")
    except FileNotFoundError:
        print("Nenhum resultado salvo ainda.")
    time.sleep(3)
