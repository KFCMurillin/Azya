import pytest
import sqlite3
import datetime
from unittest.mock import patch, MagicMock


# -----------------------------------------------
# FIXTURES
# -----------------------------------------------
@pytest.fixture(autouse=True)
def mock_terminal(monkeypatch):
    monkeypatch.setattr("utils.limpar_tela", lambda: None)
    monkeypatch.setattr("utils.carregando", lambda msg="": None)


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS urls "
        "(id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE)"
    )
    conn.commit()
    yield conn, cursor
    conn.close()


# ===============================================
# SCANNER.PY
# ===============================================
from scanner import normalizar_url


class TestNormalizarUrl:
    def test_adiciona_https_por_padrao(self):
        assert normalizar_url("example.com") == "https://example.com"

    def test_adiciona_http_quando_solicitado(self):
        assert normalizar_url("example.com", padrao="http") == "http://example.com"

    def test_mantem_https_existente(self):
        assert normalizar_url("https://example.com") == "https://example.com"

    def test_mantem_http_existente(self):
        assert normalizar_url("http://example.com") == "http://example.com"

    def test_remove_espacos(self):
        assert normalizar_url("  example.com  ") == "https://example.com"


from scanner import analisar_headers_menu


class TestAnalisarHeadersMenu:
    def test_headers_presentes(self, db, capsys):
        _, cursor = db
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "nginx", "X-Frame-Options": "DENY"}
        with patch("scanner.requests.head", return_value=mock_resp), \
             patch("builtins.input", return_value=""):
            analisar_headers_menu(cursor=cursor, url="http://example.com")
        assert "nginx" in capsys.readouterr().out

    def test_headers_ausentes(self, db, capsys):
        _, cursor = db
        mock_resp = MagicMock()
        mock_resp.headers = {}
        with patch("scanner.requests.head", return_value=mock_resp), \
             patch("builtins.input", return_value=""):
            analisar_headers_menu(cursor=cursor, url="http://example.com")
        assert "não encontrado" in capsys.readouterr().out

    def test_url_none_cancela(self, db, capsys):
        _, cursor = db
        with patch("builtins.input", return_value=""):
            analisar_headers_menu(cursor=cursor, url=None)
        assert "cancelada" in capsys.readouterr().out.lower()

    def test_excecao_rede(self, db, capsys):
        _, cursor = db
        with patch("scanner.requests.head", side_effect=Exception("timeout")), \
             patch("builtins.input", return_value=""):
            analisar_headers_menu(cursor=cursor, url="http://naoexiste.local")
        assert "Não foi possível acessar" in capsys.readouterr().out


from scanner import analisar_ssl_menu


class TestAnalisarSslMenu:
    def _cert(self, dias):
        now = datetime.datetime.utcnow()
        return {
            'notBefore': (now - datetime.timedelta(30)).strftime('%b %d %H:%M:%S %Y GMT'),
            'notAfter':  (now + datetime.timedelta(dias)).strftime('%b %d %H:%M:%S %Y GMT'),
        }

    def _mock_ssl(self, cert):
        ssock = MagicMock()
        ssock.getpeercert.return_value = cert
        ssock.__enter__ = lambda s: s
        ssock.__exit__ = MagicMock(return_value=False)
        sock = MagicMock()
        sock.__enter__ = lambda s: s
        sock.__exit__ = MagicMock(return_value=False)
        return sock, ssock

    def test_certificado_valido(self, db, capsys):
        _, cursor = db
        sock, ssock = self._mock_ssl(self._cert(90))
        with patch("scanner.socket.create_connection", return_value=sock), \
             patch("scanner.ssl.create_default_context") as ctx, \
             patch("builtins.input", return_value=""):
            ctx.return_value.wrap_socket.return_value = ssock
            analisar_ssl_menu(cursor=cursor, url="https://example.com")
        assert "válido" in capsys.readouterr().out.lower()

    def test_certificado_expirado(self, db, capsys):
        _, cursor = db
        sock, ssock = self._mock_ssl(self._cert(-5))
        with patch("scanner.socket.create_connection", return_value=sock), \
             patch("scanner.ssl.create_default_context") as ctx, \
             patch("builtins.input", return_value=""):
            ctx.return_value.wrap_socket.return_value = ssock
            analisar_ssl_menu(cursor=cursor, url="https://example.com")
        assert "expirado" in capsys.readouterr().out.lower()

    def test_excecao_ssl(self, db, capsys):
        _, cursor = db
        with patch("scanner.socket.create_connection", side_effect=Exception("refused")), \
             patch("builtins.input", return_value=""):
            analisar_ssl_menu(cursor=cursor, url="https://naoexiste.local")
        assert "Não foi possível" in capsys.readouterr().out

    def test_url_none_cancela(self, db, capsys):
        _, cursor = db
        with patch("builtins.input", return_value=""):
            analisar_ssl_menu(cursor=cursor, url=None)
        assert "cancelada" in capsys.readouterr().out.lower()


from scanner import xss_scanner_menu


class TestXssScannerMenu:
    XSS = "<script>alert('XSS')</script>"

    def _r(self, html):
        r = MagicMock()
        r.text = html
        return r

    def test_sem_formularios(self, db, capsys):
        _, cursor = db
        with patch("scanner.requests.get", return_value=self._r("<p>sem forms</p>")), \
             patch("builtins.input", return_value=""):
            xss_scanner_menu(cursor=cursor, url="http://example.com")
        assert "Nenhum formulário" in capsys.readouterr().out

    def test_payload_refletido(self, db, capsys):
        _, cursor = db
        html = '<form action="/s" method="get"><input name="q"></form>'
        with patch("scanner.requests.get", side_effect=[self._r(html), self._r(self.XSS)]), \
             patch("builtins.input", return_value=""):
            xss_scanner_menu(cursor=cursor, url="http://example.com")
        assert "possível XSS detectado" in capsys.readouterr().out

    def test_payload_nao_refletido(self, db, capsys):
        _, cursor = db
        html = '<form action="/s" method="get"><input name="q"></form>'
        with patch("scanner.requests.get", side_effect=[self._r(html), self._r("seguro")]), \
             patch("builtins.input", return_value=""):
            xss_scanner_menu(cursor=cursor, url="http://example.com")
        assert "sem reflexão" in capsys.readouterr().out

    def test_excecao_rede(self, db, capsys):
        _, cursor = db
        with patch("scanner.requests.get", side_effect=Exception("timeout")), \
             patch("builtins.input", return_value=""):
            xss_scanner_menu(cursor=cursor, url="http://x.local")
        assert "Não foi possível acessar" in capsys.readouterr().out


from scanner import port_scan_menu


class TestPortScanMenu:
    def test_porta_aberta(self, db, capsys):
        _, cursor = db
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("scanner.socket.create_connection", return_value=mock_sock), \
             patch("builtins.input", return_value=""):
            port_scan_menu(cursor=cursor, url="http://example.com")
        assert "Portas abertas" in capsys.readouterr().out

    def test_todas_fechadas(self, db, capsys):
        _, cursor = db
        with patch("scanner.socket.create_connection", side_effect=OSError("refused")), \
             patch("builtins.input", return_value=""):
            port_scan_menu(cursor=cursor, url="http://example.com")
        assert "Nenhuma porta" in capsys.readouterr().out

    def test_url_none_cancela(self, db, capsys):
        _, cursor = db
        with patch("builtins.input", return_value=""):
            port_scan_menu(cursor=cursor, url=None)
        assert "cancelada" in capsys.readouterr().out.lower()


# ===============================================
# DB.PY
# ===============================================
from db import salvar_url, listar_urls, excluir_url


class TestSalvarUrl:
    def test_salva_url_valida(self, db):
        conn, cursor = db
        with patch("builtins.input", return_value="https://teste.com"):
            salvar_url(cursor, conn)
        cursor.execute("SELECT url FROM urls WHERE url = 'https://teste.com'")
        assert cursor.fetchone() is not None

    def test_rejeita_duplicata(self, db, capsys):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://dup.com')")
        conn.commit()
        with patch("builtins.input", return_value="https://dup.com"):
            salvar_url(cursor, conn)
        assert "já cadastrada" in capsys.readouterr().out

    def test_cancela_se_vazio(self, db):
        conn, cursor = db
        with patch("builtins.input", return_value=""):
            salvar_url(cursor, conn)
        cursor.execute("SELECT COUNT(*) FROM urls")
        assert cursor.fetchone()[0] == 0

    def test_cancela_se_cancelar(self, db):
        conn, cursor = db
        with patch("builtins.input", return_value="cancelar"):
            salvar_url(cursor, conn)
        cursor.execute("SELECT COUNT(*) FROM urls")
        assert cursor.fetchone()[0] == 0


class TestListarUrls:
    def test_exibe_urls(self, db, capsys):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://a.com')")
        conn.commit()
        with patch("builtins.input", return_value=""):
            listar_urls(cursor)
        assert "https://a.com" in capsys.readouterr().out

    def test_exibe_mensagem_vazia(self, db, capsys):
        conn, cursor = db
        with patch("builtins.input", return_value=""):
            listar_urls(cursor)
        assert "Nenhuma URL salva" in capsys.readouterr().out


class TestExcluirUrl:
    def test_exclui_por_id(self, db):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://del.com')")
        conn.commit()
        cursor.execute("SELECT id FROM urls WHERE url = 'https://del.com'")
        rid = cursor.fetchone()[0]
        with patch("builtins.input", side_effect=[str(rid), "s"]):
            excluir_url(cursor, conn)
        cursor.execute("SELECT COUNT(*) FROM urls WHERE url = 'https://del.com'")
        assert cursor.fetchone()[0] == 0

    def test_cancela_confirmacao_nao(self, db):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://keep.com')")
        conn.commit()
        cursor.execute("SELECT id FROM urls WHERE url = 'https://keep.com'")
        rid = cursor.fetchone()[0]
        with patch("builtins.input", side_effect=[str(rid), "n"]):
            excluir_url(cursor, conn)
        cursor.execute("SELECT COUNT(*) FROM urls WHERE url = 'https://keep.com'")
        assert cursor.fetchone()[0] == 1

    def test_id_invalido(self, db, capsys):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://x.com')")
        conn.commit()
        with patch("builtins.input", side_effect=["9999", "s"]):
            excluir_url(cursor, conn)
        assert "não encontrado" in capsys.readouterr().out.lower()

    def test_id_nao_numerico(self, db, capsys):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://x.com')")
        conn.commit()
        with patch("builtins.input", side_effect=["abc", ""]):
            excluir_url(cursor, conn)
        assert "inválido" in capsys.readouterr().out.lower()

    def test_cancela_com_enter(self, db, capsys):
        conn, cursor = db
        cursor.execute("INSERT INTO urls (url) VALUES ('https://y.com')")
        conn.commit()
        with patch("builtins.input", return_value=""):
            excluir_url(cursor, conn)
        assert "cancelado" in capsys.readouterr().out.lower()
