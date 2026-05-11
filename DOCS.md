# AZYA Toolkit — Documentação Técnica

## Visão Geral

A AZYA é uma toolkit CLI de cybersecurity desenvolvida em Python com arquitetura modular. Centraliza operações de reconhecimento e análise de segurança em interface de menu interativo via terminal.

**Stack:** Python 3.8+, `requests`, `beautifulsoup4`, `sqlite3`, `ssl`, `socket`, `concurrent.futures`

---

## Estrutura do Projeto

| Arquivo | Responsabilidade |
|---|---|
| `main.py` | Entrada principal, navegação por menu, inicialização do banco |
| `scanner.py` | Análise de headers HTTP, SSL/TLS, scanner XSS, port scan |
| `db.py` | CRUD de URLs com SQLite |
| `banner.py` | Banner ASCII e animação de terminal |
| `utils.py` | Limpar tela, loading, salvar e mostrar resultados |
| `requirements.txt` | Dependências: `requests`, `beautifulsoup4` |
| `test_azya.py` | Suite de testes funcionais com pytest |

---

## Funcionalidades

### Análise de Headers HTTP (`analisar_headers_menu`)

Executa requisição `HEAD` no alvo e verifica presença de 15 headers de segurança.

**Headers verificados:** `Server`, `Date`, `Content-Type`, `Content-Length`, `Connection`, `Set-Cookie`, `Cache-Control`, `Expires`, `Last-Modified`, `Location`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, `Access-Control-Allow-Origin`

**Limitações:** não classifica headers ausentes por severidade nem sugere valores recomendados.

---

### Análise SSL/TLS (`analisar_ssl_menu`)

Conecta na porta 443 via `ssl` + `socket`, extrai certificado e calcula dias para expiração.

**Exibe:** data de emissão, data de expiração, dias restantes, status (válido / próximo da expiração / expirado).

**Limitações:** não verifica versão TLS (1.0/1.1/1.2/1.3), cipher suite ativo nem cadeia de certificação.

---

### Scanner XSS (`xss_scanner_menu`)

Coleta todos os `<form>` via BeautifulSoup, injeta payload `<script>alert('XSS')</script>` em campos com atributo `name` e verifica reflexão na resposta (bruta e HTML-encoded).

**Tipos cobertos:** XSS refletido via GET e POST.

**Limitações:** não cobre XSS armazenado, DOM-based, campos sem `name` ou rotas autenticadas.

---

### Port Scanner (`port_scan_menu`)

Testa 15 portas comuns em paralelo via `ThreadPoolExecutor(max_workers=15)` com timeout de 1s.

**Portas:** 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443

**Limitações:** lista fixa, sem range customizável, sem banner grabbing.

---

### Gerenciamento de URLs (`db.py`)

CRUD de URLs em SQLite (`azya.db`). Constraint `UNIQUE` na coluna `url` — duplicatas rejeitadas com mensagem.

---

## Correções Aplicadas — `scanner.py`

### Fix 1 — `datetime.utcnow()` depreciado

**Problema:** depreciado no Python 3.12+, gera `DeprecationWarning` e retorna objeto naive sem timezone.

```python
# Antes
dias_restantes = (expiry_date - datetime.datetime.utcnow()).days

# Depois
agora = datetime.datetime.now(tz=datetime.timezone.utc).replace(tzinfo=None)
dias_restantes = (expiry_date - agora).days
```

`replace(tzinfo=None)` mantém compatibilidade com `expiry_date` naive vindo do `strptime`.

---

### Fix 2 — XSS Falso Negativo com HTML Encoding

**Problema:** servidores que sanitizam retornam `&lt;script&gt;` — o check original não detectava.

```python
# Antes
if payload in r.text:

# Depois
texto_desescapado = html.unescape(r.text)
if payload in r.text or payload in texto_desescapado:
```

`html.unescape()` é stdlib, sem dependência externa. Cobre reflexão bruta e HTML-encoded.

---

### Fix 3 — Port Scan com `ThreadPoolExecutor`

**Problema:** `threading.Thread` manual sem controle de concorrência — risco de saturação de file descriptors em listas maiores.

```python
# Depois
from concurrent.futures import ThreadPoolExecutor, as_completed

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
```

Coleta resultado por retorno de função — elimina `append` compartilhado entre threads.

---

## Suite de Testes — `test_azya.py`

### Filosofia

Valida correção do código — não disponibilidade de alvos externos. Toda dependência de rede, banco e terminal é substituída por mocks.

- Execução < 1 segundo, resultado determinístico
- Isolamento total — sem efeito colateral no `azya.db` real
- Cobre cenários difíceis de reproduzir manualmente (cert expirado, rede caindo)

### Como Executar

```bash
pip install pytest
pytest test_azya.py -v

# Filtrar por módulo
pytest test_azya.py -v -k "TestXss"
pytest test_azya.py -v -k "TestDb or TestSalvar"

# Com cobertura
pip install pytest-cov
pytest test_azya.py --cov=scanner --cov=db --cov-report=term-missing
```

### Cobertura

| Módulo | Função | Testes | Cenários |
|---|---|---|---|
| `scanner.py` | `normalizar_url` | 5 | Sem prefixo, http, https, espaços |
| `scanner.py` | `analisar_headers_menu` | 4 | Presentes, ausentes, url None, exceção |
| `scanner.py` | `analisar_ssl_menu` | 4 | Válido, expirado, url None, exceção SSL |
| `scanner.py` | `xss_scanner_menu` | 4 | Sem forms, refletido, não refletido, exceção |
| `scanner.py` | `port_scan_menu` | 3 | Porta aberta, fechadas, url None |
| `db.py` | `salvar_url` | 4 | Válida, duplicata, vazio, cancelar |
| `db.py` | `listar_urls` | 2 | URLs presentes, banco vazio |
| `db.py` | `excluir_url` | 5 | Confirmada, negada, ID inválido, não numérico, Enter |
| **Total** | **8 funções** | **31** | — |

---

## Validação com Alvo Real — WebGoat

### Setup

```bash
docker run -d --name webgoat -p 8080:8080 -p 9090:9090 webgoat/goat-and-wolf
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/WebGoat/login
# 200
```

### Resultados Obtidos

| Módulo | Resultado | Observação |
|---|---|---|
| Headers HTTP | 8 ausentes | X-Frame-Options, HSTS, X-Content-Type-Options, X-XSS-Protection ausentes |
| Port Scanner | [80, 443] abertos | ngrok expõe nas portas padrão |
| XSS Scanner | Sem reflexão no /login | Rotas protegidas exigem sessão autenticada |
| SSL/TLS | Válido, 46 dias | Certificado emitido pelo ngrok |

---

## Pendências e Melhorias

| Item | Prioridade | Descrição |
|---|---|---|
| Autenticação no scanner | Alta | Suporte a cookie de sessão para rotas protegidas |
| Classificação de headers | Média | Categorizar por severidade (crítico/médio/baixo) |
| Versão TLS | Média | Detectar TLS 1.0/1.1 inseguros |
| Range de portas | Baixa | Input de range customizado |
| Banner grabbing | Baixa | Identificação de serviço nas portas abertas |
| XSS armazenado | Baixa | Ampliar scanner para XSS persistido |
