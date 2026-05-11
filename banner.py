import os
import time

BANNER_AZYA = r"""
(`-') _  (`-')   (`-')  _   
(OO ).-/ ( OO).-> .->  (OO ).-/ 
/ ,---.  ,(_/----. ,--.' ,-./ ,---.  
| \ /`.\  |__, |(`-')'.' / | \ /`.\ 
'-'|_.' | (_/ / (OO \  /  '-'|_.' | 
(| .-. |  .' .'_  | / /) (| .-. | 
| | | || |  | `-/ /`   | | | | 
`--' `--'`-------'  `--'  `--' `--'
"""

INFOS = [
    "Azya Cybersecurity Toolkit",
    "Versão: 1.0",
    "Autor: VampLin",
    "-" * 40,
    "Ferramenta para testes e análises de segurança",
]

def centralizar_texto(texto):
    try:
        colunas = os.get_terminal_size().columns
    except OSError:
        colunas = 80
    return texto.center(colunas)

def mostrar_banner_simples():
    os.system('cls' if os.name == 'nt' else 'clear')
    for linha in BANNER_AZYA.strip('\n').split('\n'):
        print(centralizar_texto(linha))
    print()

def mostrar_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    for linha in BANNER_AZYA.strip('\n').split('\n'):
        print(centralizar_texto(linha))
    print()
    for info in INFOS:
        print(centralizar_texto(info))
    print()

def animar_banner_cima_para_baixo(delay=0.11):
    try:
        colunas = os.get_terminal_size().columns
    except OSError:
        colunas = 80
    linhas = BANNER_AZYA.strip('\n').split('\n')
    for i in range(1, len(linhas) + 1):
        os.system('cls' if os.name == 'nt' else 'clear')
        for linha in linhas[:i]:
            print(centralizar_texto(linha))
        time.sleep(delay)
    print()
    for info in INFOS:
        print(centralizar_texto(info))
        time.sleep(0.09)
    print()
