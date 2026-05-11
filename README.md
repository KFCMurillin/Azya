# 🔒 AZYA — Cybersecurity Toolkit

```
(`-') _  (`-')   (`-')  _   
(OO ).-/ ( OO).-> .->  (OO ).-/ 
/ ,---.  ,(_/----. ,--.' ,-./ ,---.  
| \ /`.\  |__, |(`-')'.' / | \ /`.\ 
'-'|_.' | (_/ / (OO \  /  '-'|_.' | 
(| .-. |  .' .'_  | / /) (| .-. | 
| | | || |  | `-/ /`   | | | | 
`--' `--'`-------'  `--'  `--' `--'
```

> Ferramenta CLI para testes e análises de segurança em aplicações web.

---

## ⚙️ Funcionalidades

| Módulo | Descrição |
|---|---|
| **Headers HTTP** | Analisa a presença e configuração de headers de segurança |
| **SSL/TLS** | Verifica certificado, data de emissão, expiração e validade |
| **XSS Scanner** | Testa formulários e parâmetros com payloads de injeção |
| **Gerenciar URLs** | Salva, lista e exclui URLs alvo (SQLite local) |
| **Resultados** | Exibe histórico de resultados salvos em arquivo `.txt` |

---

## 📦 Requisitos

- Python 3.8+
- Instale as dependências:

```bash
pip install requests beautifulsoup4
```

---

## 🚀 Como usar

```bash
python main.py
```

O menu interativo será exibido com as opções disponíveis.

---

## 🗂️ Estrutura do Projeto

```
azya/
├── main.py       # Ponto de entrada, menu principal
├── scanner.py    # Módulos de análise (headers, SSL, XSS, port scan)
├── db.py         # Gerenciamento de URLs via SQLite
├── banner.py     # Banner ASCII e animações de terminal
└── utils.py      # Utilitários (limpar tela, loading, salvar resultados)
```

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida **exclusivamente para fins educacionais e testes em ambientes autorizados**. O uso indevido contra sistemas sem permissão é ilegal e antiético. O autor não se responsabiliza por mau uso.

---

## 👤 Autor

**VampLin** — Azya Cybersecurity Toolkit v1.0
