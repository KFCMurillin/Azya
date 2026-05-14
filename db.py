import sqlite3
import time
from typing import Optional
from utils import limpar_tela, carregando


# ---------------------------------------------------------------------------
# Conexão e criação de tabelas
# ---------------------------------------------------------------------------
def conectar_banco():
    conn = sqlite3.connect('azya.db')
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            id  INTEGER PRIMARY KEY,
            url TEXT NOT NULL UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alvos (
            id        INTEGER PRIMARY KEY,
            nome      TEXT NOT NULL,
            alvo      TEXT NOT NULL UNIQUE,
            protocolo TEXT NOT NULL DEFAULT 'http',
            porta     TEXT
        )
    """)

    # Sem ON DELETE CASCADE — resultados são mantidos mesmo após exclusão do alvo
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_resultados (
            id        INTEGER PRIMARY KEY,
            alvo_id   INTEGER,
            tipo_scan TEXT NOT NULL,
            resultado TEXT NOT NULL,
            criado_em TEXT NOT NULL,
            FOREIGN KEY (alvo_id) REFERENCES alvos(id)
        )
    """)

    conn.commit()
    return conn, cursor


# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------
def salvar_resultado(cursor, conn, alvo_id, tipo_scan, resultado):
    # type: (object, object, int, str, str) -> None
    """Persiste resultado de scan vinculado a um alvo."""
    import datetime
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO scan_resultados (alvo_id, tipo_scan, resultado, criado_em) VALUES (?, ?, ?, ?)",
        (alvo_id, tipo_scan, resultado, agora)
    )
    conn.commit()


def listar_resultados_alvo(cursor, alvo_id):
    # type: (object, int) -> list
    cursor.execute(
        "SELECT id, tipo_scan, resultado, criado_em "
        "FROM scan_resultados WHERE alvo_id = ? ORDER BY criado_em DESC",
        (alvo_id,)
    )
    return cursor.fetchall()


def excluir_resultados_alvo(cursor, conn, alvo_id):
    # type: (object, object, int) -> None
    cursor.execute("DELETE FROM scan_resultados WHERE alvo_id = ?", (alvo_id,))
    conn.commit()


# ---------------------------------------------------------------------------
# Helpers de exibição
# ---------------------------------------------------------------------------
def _exibir_alvos(alvos):
    # type: (list) -> None
    if not alvos:
        print("Nenhum alvo cadastrado.")
        return
    print("{:<4} {:<20} {:<30} {:<6} {}".format("ID", "Nome", "Alvo", "Proto", "Porta"))
    print("-" * 70)
    for row in alvos:
        porta = row[4] or "-"
        print("{:<4} {:<20} {:<30} {:<6} {}".format(row[0], row[1], row[2], row[3], porta))


def _montar_url_alvo(row):
    # type: (tuple) -> str
    protocolo, alvo, porta = row[3], row[2], row[4]
    return "{}://{}:{}".format(protocolo, alvo, porta) if porta else "{}://{}".format(protocolo, alvo)


# ---------------------------------------------------------------------------
# CRUD Alvos
# ---------------------------------------------------------------------------
def listar_alvos(cursor):
    # type: (object) -> list
    cursor.execute("SELECT id, nome, alvo, protocolo, porta FROM alvos ORDER BY id")
    return cursor.fetchall()


def adicionar_alvo(cursor, conn):
    limpar_tela()
    print("Adicionar Alvo\n")
    nome = input("Nome do alvo (ex: Lab DVWA): ").strip()
    if not nome or nome.lower() == 'cancelar':
        print("Cancelado."); time.sleep(1); return
    alvo = input("IP ou URL sem protocolo (ex: 192.168.1.10 ou site.com): ").strip()
    if not alvo or alvo.lower() == 'cancelar':
        print("Cancelado."); time.sleep(1); return
    protocolo = input("Protocolo [http/https] (Enter = http): ").strip().lower() or 'http'
    if protocolo not in ('http', 'https'):
        print("Protocolo inválido. Usando 'http'."); protocolo = 'http'
    porta = input("Porta (Enter para padrão): ").strip() or None
    carregando("Salvando")
    try:
        cursor.execute(
            "INSERT INTO alvos (nome, alvo, protocolo, porta) VALUES (?, ?, ?, ?)",
            (nome, alvo, protocolo, porta)
        )
        conn.commit()
        print("Alvo '{}' salvo!".format(nome))
    except sqlite3.IntegrityError:
        print("Alvo já cadastrado.")
    time.sleep(1)


def selecionar_alvo_ativo(cursor):
    # type: (object) -> Optional[dict]
    """Retorna dict com dados do alvo selecionado, ou None se cancelado."""
    limpar_tela()
    print("Selecionar Alvo Ativo\n")
    alvos = listar_alvos(cursor)
    if not alvos:
        print("Nenhum alvo cadastrado. Adicione um primeiro.")
        input("\nEnter para voltar...")
        return None
    _exibir_alvos(alvos)
    escolha = input("\nID do alvo (Enter para cancelar): ").strip()
    if not escolha:
        return None
    try:
        idx = int(escolha)
        for row in alvos:
            if row[0] == idx:
                url = _montar_url_alvo(row)
                print("\nAlvo ativo: [{}] {}".format(row[1], url))
                time.sleep(1)
                return {"id": row[0], "nome": row[1], "url": url}
        print("ID não encontrado."); time.sleep(1); return None
    except ValueError:
        print("Inválido."); time.sleep(1); return None


def excluir_alvo(cursor, conn):
    limpar_tela()
    print("Excluir Alvo\n")
    alvos = listar_alvos(cursor)
    if not alvos:
        print("Nenhum alvo para excluir."); time.sleep(2); return
    _exibir_alvos(alvos)
    escolha = input("\nID do alvo a excluir (Enter para cancelar): ").strip()
    if not escolha:
        print("Cancelado."); time.sleep(1); return
    try:
        idx = int(escolha)
        cursor.execute("SELECT nome FROM alvos WHERE id = ?", (idx,))
        result = cursor.fetchone()
        if result:
            confirm = input(
                "Excluir '{}'? Os resultados de scan vinculados serão mantidos. (s/n): ".format(result[0])
            ).lower()
            if confirm == 's':
                carregando("Excluindo")
                cursor.execute("DELETE FROM alvos WHERE id = ?", (idx,))
                conn.commit()
                print("Excluído! Resultados anteriores preservados.")
            else:
                print("Cancelado.")
        else:
            print("ID não encontrado.")
        time.sleep(1)
    except ValueError:
        print("Inválido."); time.sleep(1)


# ---------------------------------------------------------------------------
# Submenu Resultados
# ---------------------------------------------------------------------------
def submenu_resultados(cursor, conn):
    """Visualiza e gerencia resultados de scans por alvo."""
    while True:
        limpar_tela()
        print("Resultados de Scans\n")
        alvos = listar_alvos(cursor)
        if not alvos:
            print("Nenhum alvo cadastrado.")
            input("\nEnter para voltar...")
            return
        _exibir_alvos(alvos)
        print("\n  0. Voltar")
        escolha = input("\nID do alvo para ver resultados: ").strip()
        if escolha == '0' or not escolha:
            break
        try:
            alvo_id = int(escolha)
            cursor.execute("SELECT nome FROM alvos WHERE id = ?", (alvo_id,))
            row = cursor.fetchone()
            if not row:
                print("ID não encontrado."); time.sleep(1); continue
            _submenu_resultados_alvo(cursor, conn, alvo_id, row[0])
        except ValueError:
            print("Inválido."); time.sleep(1)


def _submenu_resultados_alvo(cursor, conn, alvo_id, nome_alvo):
    # type: (object, object, int, str) -> None
    while True:
        limpar_tela()
        print("Resultados — {}\n".format(nome_alvo))
        resultados = listar_resultados_alvo(cursor, alvo_id)
        if not resultados:
            print("Nenhum resultado registrado para este alvo.")
            input("\nEnter para voltar...")
            return
        for i, r in enumerate(resultados, 1):
            print("  {}. [{}] [{}]".format(i, r[3], r[1]))
        print("\n  L. Limpar todos os resultados deste alvo")
        print("  0. Voltar")
        escolha = input("\nNúmero para ver detalhe: ").strip().upper()
        if escolha == '0' or not escolha:
            break
        elif escolha == 'L':
            confirm = input("Limpar todos os resultados deste alvo? (s/n): ").lower()
            if confirm == 's':
                excluir_resultados_alvo(cursor, conn, alvo_id)
                print("Resultados removidos.")
                time.sleep(1)
                return
        else:
            try:
                idx = int(escolha) - 1
                if 0 <= idx < len(resultados):
                    r = resultados[idx]
                    limpar_tela()
                    print("[{}] {} — {}\n".format(r[3], r[1], nome_alvo))
                    print("=" * 60)
                    print(r[2])
                    print("=" * 60)
                    input("\nEnter para voltar...")
                else:
                    print("Número inválido."); time.sleep(1)
            except ValueError:
                print("Inválido."); time.sleep(1)


# ---------------------------------------------------------------------------
# Submenu Alvos
# ---------------------------------------------------------------------------
def submenu_alvos(cursor, conn, sessao):
    # type: (object, object, dict) -> None
    """
    Gerencia alvos e atualiza sessao['alvo_ativo'] in-place.
    sessao: {'alvo_ativo': None | dict}
    """
    while True:
        limpar_tela()
        ativo = sessao.get('alvo_ativo')
        status = "[ATIVO: {} — {}]".format(ativo['nome'], ativo['url']) if ativo else "[nenhum alvo ativo]"
        print("Gerenciar Alvos  {}\n".format(status))
        print("1. Adicionar alvo")
        print("2. Listar alvos")
        print("3. Selecionar alvo ativo")
        print("4. Ver resultados de scans")
        print("5. Excluir alvo")
        print("0. Voltar\n")
        escolha = input("Opção: ").strip()
        if escolha == '1':
            adicionar_alvo(cursor, conn)
        elif escolha == '2':
            limpar_tela()
            _exibir_alvos(listar_alvos(cursor))
            input("\nEnter para continuar...")
        elif escolha == '3':
            resultado = selecionar_alvo_ativo(cursor)
            if resultado:
                sessao['alvo_ativo'] = resultado
        elif escolha == '4':
            submenu_resultados(cursor, conn)
        elif escolha == '5':
            excluir_alvo(cursor, conn)
            # Deativa sessão se o alvo excluído era o ativo
            if ativo:
                still = cursor.execute(
                    "SELECT id FROM alvos WHERE id = ?", (ativo['id'],)
                ).fetchone()
                if not still:
                    sessao['alvo_ativo'] = None
        elif escolha == '0':
            carregando("Voltando")
            break
        else:
            print("Opção inválida."); time.sleep(1)


# ---------------------------------------------------------------------------
# Submenu URLs (mantido para compatibilidade)
# ---------------------------------------------------------------------------
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
            print("{}: {}".format(row[0], row[1]))
    input("\nPressione Enter para continuar")


def excluir_url(cursor, conn):
    limpar_tela()
    print("Excluir URL\n")
    cursor.execute("SELECT id, url FROM urls")
    urls = cursor.fetchall()
    if not urls:
        print("Nenhuma URL para excluir."); time.sleep(2); return
    for row in urls:
        print("{}: {}".format(row[0], row[1]))
    escolha = input("\nExcluir qual ID (Enter para cancelar): ").strip()
    if not escolha:
        print("Cancelado."); time.sleep(1); return
    try:
        idx = int(escolha)
        cursor.execute("SELECT url FROM urls WHERE id = ?", (idx,))
        result = cursor.fetchone()
        if result:
            confirm = input("Excluir '{}'? (s/n): ".format(result[0])).lower()
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
