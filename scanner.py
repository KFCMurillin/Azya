import time
import requests
import ssl
import socket
import threading
import datetime
import html
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from utils import limpar_tela, carregando

# ThreadPoolExecutor substitui threads manuais — evita saturação de descritores
from concurrent.futures import ThreadPoolExecutor, as_completed


def normalizar_url(url, padrao="https"):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"{padrao}://{url}"
    return url


def escolher_url(cursor):
    limpar_tela()
    print("Escolha a origem da URL para análise:")
    print("1. Selecionar uma URL salva")
    print("2. Digitar uma nova URL")
    escolha = input("Opção: ").strip()
    if not escolha or escolha.lower() == "cancelar":
        print("Operação cancelada.")
        time.sleep(1)
        return None
    if escolha == "1":
        cursor.execute("SELECT id, url FROM urls")
        urls = cursor.fetchall()
        if not urls:
            print("Nenhuma URL salva. Digite uma nova ou 'cancelar' para sair.")
            url = input("URL: ").strip()
            if not url or url.lower() == "cancelar":
                print("Operação cancelada.")
                time.sleep(1)
                return None
            return url
        print("\nURLs salvas:")
        for row in urls:
            print(f"{row[0]}: {row[1]}")
        idx = input("Digite o ID da URL desejada (ou 'cancelar' para sair): ").strip()
        if not idx or idx.lower() == "cancelar":
            print("Operação cancelada.")
            time.sleep(1)
            return None
        try:
            idx = int(idx)
            for row in urls:
                if row[0] == idx:
                    return row[1]
            print("ID não encontrado. Digite uma nova URL ou 'cancelar' para sair.")
            url = input("URL: ").strip()
            if not url or url.lower() == "cancelar":
                print("Operação cancelada.")
                time.sleep(1)
                return None
            return url
        except ValueError:
            print("ID inválido. Digite uma nova URL ou 'cancelar' para sair.")
            url = input("URL: ").strip()
            if not url or url.lower() == "cancelar":
                print("Operação cancelada.")
                time.sleep(1)
                return None
            return url
    else:
        url = input("URL: ").strip()
        if not url or url.lower() == "cancelar":
            print("Operação cancelada.")
            time.sleep(1)
            return None
        return url


def analisar_headers_menu(cursor=None, url=None):
    print("Análise de Headers HTTP\n")
    if not url or url.lower() == "cancelar":
        print("Operação cancelada.")
        time.sleep(1)
        return
    url = normalizar_url(url, padrao="http")
    try:
        print("\nObtendo headers...\n")
        response = requests.head(url, allow_redirects=True, timeout=5)
        headers = response.headers
        principais = [
            "Server", "Date", "Content-Type", "Content-Length", "Connection",
            "Set-Cookie", "Cache-Control", "Expires", "Last-Modified", "Location",
            "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
            "Strict-Transport-Security", "Access-Control-Allow-Origin"
        ]
        print("Checagem dos principais headers:\n")
        for h in principais:
            valor = headers.get(h)
            if valor:
                print(f"Header '{h}' encontrado: {valor}")
            else:
                print(f"Header '{h}' não encontrado na aplicação.")
    except Exception:
        print("Não foi possível acessar a URL informada. Verifique se ela existe, está correta e acessível pela internet.")
    input("\nPressione Enter para voltar...")


def analisar_ssl_menu(cursor=None, url=None):
    print("Análise de Certificado SSL/TLS\n")
    if not url or url.lower() == "cancelar":
        print("Operação cancelada.")
        time.sleep(1)
        return
    url = normalizar_url(url, padrao="https")
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            print("Não foi possível obter o certificado SSL/TLS.")
            time.sleep(2)
            return
        issue_date = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        print(f"Certificado SSL/TLS para {domain}:")
        print(f"Emitido em: {issue_date}")
        print(f"Expira em: {expiry_date}")
        # FIX: datetime.utcnow() depreciado em 3.12+ — usa timezone-aware agora
        agora = datetime.datetime.now(tz=datetime.timezone.utc).replace(tzinfo=None)
        dias_restantes = (expiry_date - agora).days
        print(f"Dias restantes para expiração: {dias_restantes} dias")
        if dias_restantes < 0:
            print("O certificado está expirado!")
        elif dias_restantes < 30:
            print("O certificado está próximo da expiração.")
        else:
            print("O certificado está válido.")
    except Exception:
        print("Não foi possível acessar o domínio informado via HTTPS. Verifique se ele suporta SSL/TLS e está online.")
    input("\nPressione Enter para voltar...")


def xss_scanner_menu(cursor=None, url=None):
    print("Scanner XSS\n")
    if not url or url.lower() == "cancelar":
        print("Operação cancelada.")
        time.sleep(1)
        return
    url = normalizar_url(url, padrao="http")
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            print("Nenhum formulário encontrado na página.")
        else:
            print(f"{len(forms)} formulário(s) encontrado(s). Testando...\n")
            for i, form in enumerate(forms, 1):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                full_url = urljoin(url, action)
                data = {}
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    if name:
                        data[name] = payload
                try:
                    if method == 'post':
                        r = requests.post(full_url, data=data, timeout=5)
                    else:
                        r = requests.get(full_url, params=data, timeout=5)
                    # FIX: desescapa HTML antes de checar — evita falso negativo
                    # quando servidor retorna &lt;script&gt; ao invés do payload bruto
                    texto_desescapado = html.unescape(r.text)
                    if payload in r.text or payload in texto_desescapado:
                        print(f"[!] Formulário {i}: possível XSS detectado em {full_url}")
                    else:
                        print(f"[✓] Formulário {i}: sem reflexão de payload em {full_url}")
                except Exception:
                    print(f"Erro ao testar formulário {i}.")
    except Exception:
        print("Não foi possível acessar a URL informada.")
    input("\nPressione Enter para voltar...")


def port_scan_menu(cursor=None, url=None):
    print("Port Scanner\n")
    if not url or url.lower() == "cancelar":
        print("Operação cancelada.")
        time.sleep(1)
        return
    url = normalizar_url(url)
    host = url.replace("https://", "").replace("http://", "").split("/")[0]
    portas_comuns = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    abertas = []

    def verificar_porta(porta):
        try:
            with socket.create_connection((host, porta), timeout=1):
                return porta
        except Exception:
            return None

    # FIX: ThreadPoolExecutor com max_workers fixo — evita saturação de descritores
    # sob listas grandes de portas. Escolhido sobre threading.Thread manual porque
    # oferece controle de concorrência, coleta de resultado e tratamento de exceção.
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(verificar_porta, p): p for p in portas_comuns}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado is not None:
                abertas.append(resultado)

    if abertas:
        print(f"Portas abertas em {host}: {sorted(abertas)}")
    else:
        print(f"Nenhuma porta comum aberta encontrada em {host}.")
    input("\nPressione Enter para voltar...")


def menu_cybersecurity(cursor):
    while True:
        limpar_tela()
        print("CyberSecurity\n")
        print("1. Análise de Headers HTTP")
        print("2. Análise de Certificado SSL/TLS")
        print("3. Scanner XSS")
        print("4. Port Scanner")
        print("0. Voltar\n")
        escolha = input("Escolha uma opção: ").strip()
        if escolha in ["1", "2", "3", "4"]:
            url = escolher_url(cursor)
            limpar_tela()
            if escolha == "1":
                analisar_headers_menu(cursor, url)
            elif escolha == "2":
                analisar_ssl_menu(cursor, url)
            elif escolha == "3":
                xss_scanner_menu(cursor, url)
            elif escolha == "4":
                port_scan_menu(cursor, url)
        elif escolha == "0":
            carregando("Voltando")
            break
        else:
            print("Opção inválida.")
            time.sleep(1)
