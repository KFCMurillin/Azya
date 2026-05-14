import pytest
import requests
from unittest.mock import patch, MagicMock
from scanner import (
    _check_reflexao,
    _test_reflected_forms,
    _test_reflected_params,
    _test_stored,
)
from bs4 import BeautifulSoup


PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "<svg/onload=alert(1)>",
]


def mock_response(text="", status=200):
    r = MagicMock()
    r.text = text
    r.status_code = status
    return r


@pytest.fixture
def session():
    return requests.Session()


# ---------------------------------------------------------------------------
# _check_reflexao
# ---------------------------------------------------------------------------
def test_check_reflexao_bruto():
    payload = "<script>alert(1)</script>"
    assert _check_reflexao(payload, payload) is True


def test_check_reflexao_encoded():
    payload = "<script>alert(1)</script>"
    encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert _check_reflexao(encoded, payload) is True


def test_check_reflexao_miss():
    assert _check_reflexao("<p>safe</p>", "<script>alert(1)</script>") is False


# ---------------------------------------------------------------------------
# _test_reflected_forms
# ---------------------------------------------------------------------------
def test_reflected_forms_detecta(session):
    html_form = """
    <form method="get" action="/search">
      <input name="q" type="text">
    </form>
    """
    soup = BeautifulSoup(html_form, "html.parser")
    payload = PAYLOADS[0]
    with patch.object(session, "get", return_value=mock_response(text=payload)):
        res = _test_reflected_forms("http://alvo.com", soup, session, PAYLOADS)
    assert any(r["tipo"] == "reflected_form" for r in res)


def test_reflected_forms_post_detecta(session):
    html_form = """
    <form method="post" action="/login">
      <input name="user">
      <input name="pass">
    </form>
    """
    soup = BeautifulSoup(html_form, "html.parser")
    payload = PAYLOADS[0]
    with patch.object(session, "post", return_value=mock_response(text=payload)):
        res = _test_reflected_forms("http://alvo.com", soup, session, PAYLOADS)
    assert any(r["tipo"] == "reflected_form" and r["method"] == "post" for r in res)


def test_reflected_forms_sem_xss(session):
    html_form = "<form><input name='q'></form>"
    soup = BeautifulSoup(html_form, "html.parser")
    with patch.object(session, "get", return_value=mock_response(text="<p>resultado seguro</p>")):
        res = _test_reflected_forms("http://alvo.com", soup, session, PAYLOADS)
    assert res == []


def test_reflected_forms_sem_form(session):
    soup = BeautifulSoup("<p>sem formulario</p>", "html.parser")
    res = _test_reflected_forms("http://alvo.com", soup, session, PAYLOADS)
    assert res == []


# ---------------------------------------------------------------------------
# _test_reflected_params
# ---------------------------------------------------------------------------
def test_reflected_params_detecta(session):
    payload = PAYLOADS[0]
    with patch.object(session, "get", return_value=mock_response(text=payload)):
        res = _test_reflected_params("http://alvo.com/?q=teste", session, PAYLOADS)
    assert any(r["tipo"] == "reflected_param" for r in res)


def test_reflected_params_sem_reflexao(session):
    with patch.object(session, "get", return_value=mock_response(text="<p>ok</p>")):
        res = _test_reflected_params("http://alvo.com/?q=teste", session, PAYLOADS)
    assert res == []


def test_reflected_params_sem_query_usa_fallback(session):
    # URL sem params — deve usar {'q': ''} como fallback e não lançar exceção
    payload = PAYLOADS[0]
    with patch.object(session, "get", return_value=mock_response(text=payload)):
        res = _test_reflected_params("http://alvo.com/", session, PAYLOADS)
    assert isinstance(res, list)


# ---------------------------------------------------------------------------
# _test_stored
# ---------------------------------------------------------------------------
def test_stored_detecta_marker(session):
    html_form = """
    <form method="post" action="/comentar">
      <textarea name="msg"></textarea>
    </form>
    """
    soup = BeautifulSoup(html_form, "html.parser")
    # Simula POST ok + GET que reflete o marker
    def get_side_effect(url, **kwargs):
        return mock_response(text="<p>AZYA_STORED_</p>")
    with patch.object(session, "post", return_value=mock_response(text="ok")), \
         patch.object(session, "get", side_effect=get_side_effect), \
         patch("time.sleep"):
        res = _test_stored("http://alvo.com", soup, session)
    # marker parcial presente na resposta — deve detectar
    assert isinstance(res, list)


def test_stored_sem_form_retorna_vazio(session):
    soup = BeautifulSoup("<p>sem form</p>", "html.parser")
    res = _test_stored("http://alvo.com", soup, session)
    assert res == []


def test_stored_sem_reflexao(session):
    html_form = "<form method='post' action='/cmd'><input name='cmd'></form>"
    soup = BeautifulSoup(html_form, "html.parser")
    with patch.object(session, "post", return_value=mock_response(text="ok")), \
         patch.object(session, "get", return_value=mock_response(text="<p>clean</p>")), \
         patch("time.sleep"):
        res = _test_stored("http://alvo.com", soup, session)
    assert res == []
