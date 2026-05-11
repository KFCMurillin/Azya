# Changelog — AZYA Toolkit

## [0.1.1] — 2026-05-11

### Corrigido
- **`scanner.py`** — `datetime.utcnow()` substituído por `datetime.now(tz=datetime.timezone.utc)` para compatibilidade com Python 3.12+
- **`scanner.py`** — XSS scanner agora aplica `html.unescape()` antes de verificar reflexão do payload, eliminando falso negativo em servidores que retornam output HTML-encoded
- **`scanner.py`** — Port scan migrado de `threading.Thread` manual para `ThreadPoolExecutor(max_workers=15)`, eliminando risco de saturação de file descriptors e race condition

### Adicionado
- **`test_azya.py`** — Suite de 31 testes funcionais com pytest cobrindo `scanner.py` e `db.py` com mocks completos de rede, banco e terminal
- **`DOCS.md`** — Documentação técnica completa do projeto
- **`CHANGELOG.md`** — Histórico de versões

### Validado
- AZYA testada contra WebGoat via Docker + ngrok com todos os 4 módulos operacionais

---

## [0.1.0] — 2025-08-05

### Adicionado
- Estrutura modular inicial: `main.py`, `scanner.py`, `db.py`, `banner.py`, `utils.py`
- Análise de Headers HTTP
- Análise de Certificado SSL/TLS
- Scanner XSS (formulários GET/POST)
- Port Scanner com threading
- Gerenciamento de URLs via SQLite
