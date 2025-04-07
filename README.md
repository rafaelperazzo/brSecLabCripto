# 🔐 brseclabcripto – Pacote de Criptografia em Python

![Alt text](https://hjgxogrnwlrwmgipixgo.supabase.co/storage/v1/object/public/fotos//logo.jpg)

**brseclabcripto** é um pacote simples e poderoso de criptografia desenvolvido em **Python**, oferecendo funcionalidades essenciais de criptografia simétrica, e hashing. Ideal para aprendizado, prototipagem ou aplicações que precisam de uma camada extra de segurança nos dados.

## ✨ Funcionalidades

- 🔒 **Criptografia Simétrica (AES-256-GCM)**
  - Criptografa e descriptografa dados usando uma chave secreta.
  
- 🧾 **Hash de Dados (SHA3-256)**
  - Criação de hash para verificar integridade de mensagens.

- 🧾 **Hash de Senhas (argon2Id)**
  - Criação de hash armazenamento seguro de senhas.
  - Verificação de senhas usando o algoritmo Argon2Id.
  - Proteção contra ataques de força bruta e dicionário.

- 🔐 **Geração de Chaves Seguras**
  - Geração de chaves criptograficamente seguras com Python Secrets.

- 📦 Design modular e extensível

## 💻 Instalação

Você pode instalar o pacote localmente clonando o repositório:

```bash
pip install brseclabcripto
```

## 💣 Uso

### 📘 Importando o módulo

```python
from brseclabcripto import cripto2
```

### 🔑 Gerar chave

```python
key = cripto2.generate_aes_key()
```

### 🔐 Criptografar string

```python
ciphertext = cripto2.aes_gcm_encrypt(key,"TEXTO")
```

### 🔓 Decriptar

```python
decriptado = cripto2.aes_gcm_decrypt(key,ciphertext)
```

### 🧾 Gerar hash com argon2id

```python
hash_argon = hash_argon2id(key,password)
```

### ⁉️ Verificar hash argon2id

```python
hash_argon2id_verify(hash_argon, key,password)
```

## 💸 Licença

Este projeto está licenciado sob a Licença GPL-3.0. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 👥 Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir um issue.

## 👨 Autor

RAFAEL PERAZZO
