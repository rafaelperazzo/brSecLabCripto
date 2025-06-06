# 🔐 brseclabcripto – Pacote de Criptografia em Python

![Alt text](https://hjgxogrnwlrwmgipixgo.supabase.co/storage/v1/object/public/fotos//logo.jpg)

**brseclabcripto** é um pacote simples e poderoso de criptografia desenvolvido em **Python**, oferecendo funcionalidades essenciais de criptografia simétrica, e hashing. Ideal para aprendizado, prototipagem ou aplicações que precisam de uma camada extra de segurança nos dados.

## ✨ Funcionalidades

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
- 🔒 **Criptografia Simétrica (AES-256-GCM, GNUPG)**
=======
- 🔒 **Criptografia Simétrica (AES-256-GCM)**
>>>>>>> develop
=======
- 🔒 **Criptografia Simétrica (AES-256-GCM)**
=======
- 🔒 **Criptografia Simétrica (AES-256-GCM, GNUPG)**
>>>>>>> 08fe7ee (docs: Incluídas novas informações no readme)
>>>>>>> develop
=======
- 🔒 **Criptografia Simétrica (AES-256-GCM)**
>>>>>>> develop
  - Criptografa e descriptografa dados usando uma chave secreta.
  
- 🧾 **Hash de Dados (SHA3-256)**
  - Criação de hash para verificar integridade de mensagens.

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
- 🧾 **Hash de Senhas (argon2Id com HMAC SHA3-256)**
  - Criação de hash armazenamento seguro de senhas.
=======
=======
>>>>>>> develop
=======
>>>>>>> develop
- 🧾 **Hash de Senhas (argon2Id)**
  - Criação de hash armazenamento seguro de senhas.
  - Verificação de senhas usando o algoritmo Argon2Id.
  - Proteção contra ataques de força bruta e dicionário.
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> develop
=======
=======
- 🧾 **Hash de Senhas (argon2Id com HMAC SHA3-256)**
  - Criação de hash armazenamento seguro de senhas.
>>>>>>> d5013cb (docs: Incluído recurso do argon2 no readme)
>>>>>>> develop
=======
>>>>>>> develop

- 🔐 **Geração de Chaves Seguras**
  - Geração de chaves criptograficamente seguras com Python Secrets.

- 📦 Design modular e extensível

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
## 💻 Instalação
=======
>>>>>>> develop
## Requisitos

- Python 3.10 ou superior

## 📦 Instalação
<<<<<<< HEAD
=======
## 💻 Instalação
>>>>>>> develop
=======
>>>>>>> 08fe7ee (docs: Incluídas novas informações no readme)
>>>>>>> develop
=======
## 💻 Instalação
>>>>>>> develop

Você pode instalar o pacote localmente instalando o pacote pip:

```bash
pip install brseclabcripto
```

## 💣 Uso

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
Em construção

## Licença

Este projeto está licenciado sob a GNU GENERAL PUBLIC LICENSE. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir um **issue**.

## Autor

RAFAEL PERAZZO BARBOSA MOTA
=======
=======
>>>>>>> develop
=======
>>>>>>> develop
### 📘 Importando o módulo

```python
from brseclabcripto import cripto2
from brseclabcripto.cripto3 import SecCripto #classe
```

```python
from brseclabcripto.cripto3 import SecCripto #classe
```

### 🔑 Gerar chave

```python
key = cripto2.generate_aes_key()
```

```python
key = SecCripto.generate_aes_key()
```

### 🔐 Criptografar string

```python
ciphertext = cripto2.aes_gcm_encrypt(key,"TEXTO")
```

```python
ciphertext = SecCripto.aes_gcm_encrypt("TEXTO")
```

### 🔓 Decriptar

```python
decriptado = cripto2.aes_gcm_decrypt(key,ciphertext)
```

```python
decriptado = SecCripto.aes_gcm_decrypt(ciphertext)
```

### 🧾 Gerar hash com argon2id

```python
hash_argon = hash_argon2id(key,password)
```

```python
hash_argon = SecCripto.hash_argon2id(password)
```

### ⁉️ Verificar hash argon2id

```python
hash_argon2id_verify(hash_argon, key,password)
```

```python
SecCripto.hash_argon2id_verify(hash_argon, password)
```

## 💸 Licença

Este projeto está licenciado sob a Licença GPL-3.0. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 👥 Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir um issue.

## 👨 Autor

RAFAEL PERAZZO
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> develop
=======
=======
Em construção

## Licença

Este projeto está licenciado sob a GNU GENERAL PUBLIC LICENSE. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir um **issue**.

## Autor

RAFAEL PERAZZO BARBOSA MOTA
>>>>>>> 08fe7ee (docs: Incluídas novas informações no readme)
>>>>>>> develop
=======
>>>>>>> develop
