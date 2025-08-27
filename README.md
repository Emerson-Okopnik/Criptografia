# 🔐 Crypto Demo PHP — Auditoria e Segurança

Implementação didática de **criptografia simétrica** (AES-256-GCM) e **assimétrica** (RSA-OAEP) em PHP, com modo **híbrido** (AES para dados + RSA para proteger a chave de sessão).

> **Contexto acadêmico**  
> Este repositório foi desenvolvido como **atividade da disciplina _Auditoria e Segurança_**, demonstrando boas práticas de confidencialidade, integridade e gestão de chaves.

---

## 📦 O que tem aqui

- `crypto_demo.php` — CLI com subcomandos para:
  - `gen-keys` → gerar par RSA (4096 bits)
  - `sym:enc` / `sym:dec` → cifrar/decifrar com **senha** (AES-256-GCM + PBKDF2)
  - `hybrid:enc` / `hybrid:dec` → cifrar/decifrar **híbrido** (AES-256-GCM + RSA-OAEP)

---

## 🧰 Requisitos

- PHP **8.0+** com extensão **OpenSSL** habilitada
- OpenSSL disponível/funcional no ambiente do PHP

Verifique:
```bash
php -m | grep -i openssl
php -i | grep -i "OpenSSL support"
