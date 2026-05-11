import sqlite3
import time
from utils import limpar_tela, carregando

def conectar_banco():
    conn = sqlite3.connect('azya.db')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE)")
    conn.commit()
    return conn, cursor

def submenu_urls(cursor, conn):
    while True:
        limpar_tela()
        print("Gerenciamento de URLs\n")
        print("1. Salvar URL")
        print("2. Listar URLs")
        print("3. Excluir URL")
        print("0. Voltar\n")
        escolha = input("Escolha uma opção: ").strip()
        if escolha == "1":
            salvar_url(cursor, conn)
        elif escolha == "2":
            listar_urls(cursor)
        elif escolha == "3":
            excluir_url(cursor, conn)
        elif escolha == "0":
            carregando("Voltando")
            break
        else:
            print("Opção inválida.")
            time.sleep(1)

def salvar_url(cursor, conn):
    limpar_tela()
    print("Salvar URL (ou 'cancelar')\n")
    url = input("URL: ").strip()
    if not url or url.lower() == 'cancelar':
        print("Cancelado."); time.sleep(1); return
    carregando("Salvando")
    try:
        cursor.execute("INSERT INTO urls (url) VALUES (?)", (url,))
        conn.commit()
        print("Salvo!")
    except sqlite3.IntegrityError:
        print("URL já cadastrada!")
    time.sleep(1)

def listar_urls(cursor):
    limpar_tela()
    print("URLs Salvas\n")
    cursor.execute("SELECT id, url FROM urls")
    urls = cursor.fetchall()
    if not urls:
        print("Nenhuma URL salva.")
    else:
        for row in urls:
            print(f"{row[0]}: {row[1]}")
    input("\nPressione Enter para continuar")

def excluir_url(cursor, conn):
    limpar_tela()
    print("Excluir URL\n")
    cursor.execute("SELECT id, url FROM urls")
    urls = cursor.fetchall()
    if not urls:
        print("Nenhuma URL para excluir."); time.sleep(2); return
    for row in urls:
        print(f"{row[0]}: {row[1]}")
    escolha = input("\nExcluir qual ID (Enter para cancelar): ").strip()
    if not escolha:
        print("Cancelado."); time.sleep(1); return
    try:
        idx = int(escolha)
        cursor.execute("SELECT url FROM urls WHERE id = ?", (idx,))
        result = cursor.fetchone()
        if result:
            confirm = input(f"Excluir '{result[0]}'? (s/n): ").lower()
            if confirm == 's':
                carregando("Excluindo")
                cursor.execute("DELETE FROM urls WHERE id = ?", (idx,))
                conn.commit()
                print("Excluído!")
            else:
                print("Cancelado.")
        else:
            print("ID não encontrado.")
        time.sleep(1)
    except ValueError:
        print("Inválido."); time.sleep(1)
