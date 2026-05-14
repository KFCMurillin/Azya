import os
import json
import time
import html
import ssl
import socket
import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from utils import limpar_tela, carregando
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Payloads externos
# ---------------------------------------------------------------------------
_PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), "payloads", "xss_payloads.json")

def _carregar_payloads():
    with open(_PAYLOADS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Helpers de URL
# ---------------------------------------------------------------------------
def normalizar_url(url, padrao="https"):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "{}://{}".format(padrao, url)
    return url


def _resolver_url(cursor, conn, sessao):
    """
    Resolucao de URL para o scan:
      1. Alvo ativo na sessao  -> usa direto, sem prompt.
      2. Sem alvo ativo        -> lista alvos cadastrados OU permite digitar avulso.
    Scans avulsos (sem alvo_id) nao sao salvos no banco.
    """
    ativo = sessao.get('alvo_ativo') if sessao else None
    if ativo:
        print("Usando alvo ativo: [{}] {}".format(ativo['nome'], ativo['url']))
        time.sleep(1)
        return ativo['url']

    # Sem alvo ativo: oferece alvos cadastrados ou digitacao avulsa
    limpar_tela()
    print("Nenhum alvo ativo.\n")
    from db import listar_alvos, _montar_url_alvo
    alvos = listar_alvos(cursor)
    if alvos:
        from db import _exibir_alvos
        _exibir_alvos(alvos)
        print("  A. Digitar URL avulsa (sem salvar)")
        print("  0. Cancelar")
        escolha = input("\nID do alvo ou 'A' para avulso: ").strip().upper()
        if escolha == '0' or not escolha:
            return None
        if escolha == 'A':
            return _pedir_url_avulsa()
        try:
            idx = int(escolha)
            for row in alvos:
                if row[0] == idx:
                    return _montar_url_alvo(row)
            print("ID nao encontrado."); time.sleep(1); return None
        except ValueError:
            print("Invalido."); time.sleep(1); return None
    else:
        print("Nenhum alvo cadastrado.")
        print("1. Digitar URL avulsa")
        print("0. Cancelar")
        escolha = input("Opcao: ").strip()
        if escolha == '1':
            return _pedir_url_avulsa()
        return None


def _pedir_url_avulsa():
    url = input("URL (ex: http://192.168.1.10): ").strip()
    if not url or url.lower() == 'cancelar':
        print("Cancelado."); time.sleep(1); return None
    return url


def _get_alvo_id(sessao):
    ativo = sessao.get('alvo_ativo') if sessao else None
    return ativo['id'] if ativo else None


# ---------------------------------------------------------------------------
# Header Analysis
# ---------------------------------------------------------------------------
def analisar_headers_menu(cursor=None, conn=None, sessao=None, url=None):
    print("Analise de Headers HTTP\n")
    if not url or url.lower() == "cancelar":
        print("Operacao cancelada."); time.sleep(1); return
    url = normalizar_url(url, padrao="http")
    linhas = []
    try:
        print("\nObtendo headers...\n")
        response = requests.head(url, allow_redirects=True, timeout=5)
        principais = [
            "Server", "Date", "Content-Type", "Content-Length", "Connection",
            "Set-Cookie", "Cache-Control", "Expires", "Last-Modified", "Location",
            "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
            "Strict-Transport-Security", "Access-Control-Allow-Origin"
        ]
        print("Checagem dos principais headers:\n")
        for h in principais:
            valor = response.headers.get(h)
            linha = "Header '{}' encontrado: {}".format(h, valor) if valor else "Header '{}' nao encontrado.".format(h)
            print(linha)
            linhas.append(linha)
    except Exception:
        print("Nao foi possivel acessar a URL informada.")
        input("\nPressione Enter para voltar..."); return

    if conn and sessao:
        alvo_id = _get_alvo_id(sessao)
        if alvo_id and linhas:
            from db import salvar_resultado
            salvar_resultado(cursor, conn, alvo_id, "headers", "\n".join(linhas))
            print("\n[+] Resultado salvo.")

    input("\nPressione Enter para voltar...")


# ---------------------------------------------------------------------------
# SSL Analysis
# ---------------------------------------------------------------------------
def analisar_ssl_menu(cursor=None, conn=None, sessao=None, url=None):
    print("Analise de Certificado SSL/TLS\n")
    if not url or url.lower() == "cancelar":
        print("Operacao cancelada."); time.sleep(1); return
    url = normalizar_url(url, padrao="https")
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    linhas = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            print("Nao foi possivel obter o certificado SSL/TLS."); time.sleep(2); return
        issue_date = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        agora = datetime.datetime.now(tz=datetime.timezone.utc).replace(tzinfo=None)
        dias_restantes = (expiry_date - agora).days
        status = "EXPIRADO" if dias_restantes < 0 else ("PROXIMO DA EXPIRACAO" if dias_restantes < 30 else "VALIDO")
        linhas = [
            "Dominio: {}".format(domain),
            "Emitido em: {}".format(issue_date),
            "Expira em: {}".format(expiry_date),
            "Dias restantes: {}".format(dias_restantes),
            "Status: {}".format(status),
        ]
        for l in linhas:
            print(l)
    except Exception:
        print("Nao foi possivel acessar o dominio via HTTPS.")
        input("\nPressione Enter para voltar..."); return

    if conn and sessao:
        alvo_id = _get_alvo_id(sessao)
        if alvo_id and linhas:
            from db import salvar_resultado
            salvar_resultado(cursor, conn, alvo_id, "ssl", "\n".join(linhas))
            print("\n[+] Resultado salvo.")

    input("\nPressione Enter para voltar...")


# ---------------------------------------------------------------------------
# XSS Scanner - sub-rotinas
# ---------------------------------------------------------------------------
def _check_reflexao(texto, payload):
    return payload in texto or payload in html.unescape(texto)


def _test_reflected_forms(url, soup, session, payloads):
    resultados = []
    for i, form in enumerate(soup.find_all('form'), 1):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        full_url = urljoin(url, action)
        for payload in payloads:
            data = {inp.get('name'): payload for inp in form.find_all('input') if inp.get('name')}
            if not data:
                continue
            try:
                r = (session.post(full_url, data=data, timeout=5)
                     if method == 'post'
                     else session.get(full_url, params=data, timeout=5))
                if _check_reflexao(r.text, payload):
                    resultados.append({"tipo": "reflected_form", "form": i,
                                       "url": full_url, "method": method, "payload": payload})
            except Exception:
                pass
    return resultados


def _test_reflected_params(url, session, payloads):
    resultados = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query) or {"q": [""]}
    for payload in payloads:
        teste_params = {k: payload for k in params}
        test_url = urlunparse(parsed._replace(query=urlencode(teste_params, doseq=True)))
        try:
            r = session.get(test_url, timeout=5)
            if _check_reflexao(r.text, payload):
                resultados.append({"tipo": "reflected_param", "url": test_url, "payload": payload})
        except Exception:
            pass
    return resultados


def _test_stored(url, soup, session):
    resultados = []
    marker = "AZYA_STORED_{}".format(int(time.time()))
    payload_stored = "<script>/*{}*/alert('STORED_XSS')</script>".format(marker)
    for i, form in enumerate(soup.find_all('form'), 1):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        full_url = urljoin(url, action)
        data = {inp.get('name'): payload_stored
                for inp in form.find_all(['input', 'textarea']) if inp.get('name')}
        if not data:
            continue
        try:
            if method == 'post':
                session.post(full_url, data=data, timeout=5)
            else:
                session.get(full_url, params=data, timeout=5)
            time.sleep(1)
            r_check = session.get(url, timeout=5)
            if marker in r_check.text or marker in html.unescape(r_check.text):
                resultados.append({"tipo": "stored_xss", "form": i,
                                   "submit_url": full_url, "check_url": url, "marker": marker})
        except Exception:
            pass
    return resultados


def _formatar_resultados_xss(todos):
    if not todos:
        return "[+] Nenhuma vulnerabilidade XSS detectada com os payloads utilizados."
    linhas = []
    for res in todos:
        tipo = res['tipo']
        if tipo == 'reflected_form':
            linhas.append("[!] REFLECTED_FORM | Form {} | {} {}".format(
                res['form'], res['method'].upper(), res['url']))
            linhas.append("    payload: {}".format(res['payload']))
        elif tipo == 'reflected_param':
            linhas.append("[!] REFLECTED_PARAM | {}".format(res['url']))
            linhas.append("    payload: {}".format(res['payload']))
        elif tipo == 'stored_xss':
            linhas.append("[!] STORED_XSS | submit: {} | marker: {}".format(
                res['submit_url'], res['marker']))
    return "\n".join(linhas)


# ---------------------------------------------------------------------------
# XSS Scanner - menu principal
# ---------------------------------------------------------------------------
def xss_scanner_menu(cursor=None, conn=None, sessao=None, url=None):
    print("Scanner XSS\n")
    if not url or url.lower() == "cancelar":
        print("Operacao cancelada."); time.sleep(1); return
    url = normalizar_url(url, padrao="http")
    try:
        dados = _carregar_payloads()
    except FileNotFoundError:
        print("[ERRO] Arquivo de payloads nao encontrado: {}".format(_PAYLOADS_PATH))
        input("\nPressione Enter para voltar..."); return

    payloads_reflected = dados["reflected"]
    gathering = dados["gathering"]

    print("Modo de scan XSS:")
    print("  1. Reflected (forms + query params)")
    print("  2. Stored")
    print("  3. Reflected + Stored")
    print("  4. Mostrar Gathering Payloads")
    modo = input("Modo: ").strip()

    session = requests.Session()
    try:
        r = session.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
    except Exception:
        print("Nao foi possivel acessar a URL informada.")
        input("\nPressione Enter para voltar..."); return

    todos = []
    if modo in ("1", "3"):
        print("\n[*] Testando Reflected XSS...")
        todos += _test_reflected_forms(url, soup, session, payloads_reflected)
        todos += _test_reflected_params(url, session, payloads_reflected)
    if modo in ("2", "3"):
        print("[*] Testando Stored XSS...")
        todos += _test_stored(url, soup, session)
    if modo == "4":
        print("\n[*] Gathering Payloads (substitua SEU_COLECTOR pelo seu listener):\n")
        for nome, payload in gathering.items():
            print("  [{}]\n    {}\n".format(nome, payload))
        input("\nPressione Enter para voltar..."); return

    print("\n" + "=" * 60)
    resultado_txt = _formatar_resultados_xss(todos)
    print(resultado_txt)
    print("=" * 60)

    if conn and sessao and modo in ("1", "2", "3"):
        alvo_id = _get_alvo_id(sessao)
        if alvo_id:
            from db import salvar_resultado
            tipo_label = {"1": "xss_reflected", "2": "xss_stored", "3": "xss_reflected+stored"}.get(modo, "xss")
            salvar_resultado(cursor, conn, alvo_id, tipo_label, resultado_txt)
            print("\n[+] Resultado salvo.")

    input("\nPressione Enter para voltar...")


# ---------------------------------------------------------------------------
# Port Scanner
# ---------------------------------------------------------------------------
def port_scan_menu(cursor=None, conn=None, sessao=None, url=None):
    print("Port Scanner\n")
    if not url or url.lower() == "cancelar":
        print("Operacao cancelada."); time.sleep(1); return
    url = normalizar_url(url)
    host = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    linhas = []
    portas_comuns = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    abertas = []

    def verificar_porta(porta):
        try:
            with socket.create_connection((host, porta), timeout=1):
                return porta
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(verificar_porta, p): p for p in portas_comuns}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado is not None:
                abertas.append(resultado)

    if abertas:
        linha = "Portas abertas em {}: {}".format(host, sorted(abertas))
    else:
        linha = "Nenhuma porta comum aberta encontrada em {}.".format(host)
    print(linha)
    linhas.append(linha)

    if conn and sessao:
        alvo_id = _get_alvo_id(sessao)
        if alvo_id:
            from db import salvar_resultado
            salvar_resultado(cursor, conn, alvo_id, "port_scan", "\n".join(linhas))
            print("\n[+] Resultado salvo.")

    input("\nPressione Enter para voltar...")


# ---------------------------------------------------------------------------
# Menu CyberSecurity
# ---------------------------------------------------------------------------
def menu_cybersecurity(cursor, conn=None, sessao=None):
    while True:
        limpar_tela()
        ativo = sessao.get('alvo_ativo') if sessao else None
        status = ("[Alvo: {} - {}]".format(ativo['nome'], ativo['url'])
                  if ativo else "[nenhum alvo ativo - sera solicitado por scan]")
        print("CyberSecurity  {}\n".format(status))
        print("1. Analise de Headers HTTP")
        print("2. Analise de Certificado SSL/TLS")
        print("3. Scanner XSS")
        print("4. Port Scanner")
        print("0. Voltar\n")
        escolha = input("Escolha uma opcao: ").strip()
        if escolha in ["1", "2", "3", "4"]:
            url = _resolver_url(cursor, conn, sessao)
            if not url:
                continue
            limpar_tela()
            if escolha == "1":
                analisar_headers_menu(cursor, conn, sessao, url)
            elif escolha == "2":
                analisar_ssl_menu(cursor, conn, sessao, url)
            elif escolha == "3":
                xss_scanner_menu(cursor, conn, sessao, url)
            elif escolha == "4":
                port_scan_menu(cursor, conn, sessao, url)
        elif escolha == "0":
            carregando("Voltando")
            break
        else:
            print("Opcao invalida."); time.sleep(1)
