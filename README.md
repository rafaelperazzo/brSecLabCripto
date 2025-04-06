# 🔐 brseclabcripto – Pacote de Criptografia em Python

**brseclabcripto** é um pacote simples e poderoso de criptografia desenvolvido em **Python**, oferecendo funcionalidades essenciais de criptografia simétrica, e hashing. Ideal para aprendizado, prototipagem ou aplicações que precisam de uma camada extra de segurança nos dados.

## ✨ Funcionalidades

- 🔒 **Criptografia Simétrica (AES)**
  - Criptografa e descriptografa dados usando uma chave secreta.
  
- 🧾 **Hash de Dados (SHA3-256)**
  - Criação de hash para verificar integridade de mensagens.

- 🔐 **Geração de Chaves Seguras**
  - Geração de chaves criptograficamente seguras.

- 📦 Design modular e extensível

## 📦 Instalação

Você pode instalar o pacote localmente clonando o repositório:

```bash
pip install brseclabcripto
```

## Uso

### Gerar chave

```python
key = cripto2.generate_aes_key()
```

### Criptografar string

```python
ciphertext = cripto2.aes_gcm_encrypt(key,"TEXTO")
```

### Decriptar

```python
decriptado = cripto2.aes_gcm_decrypt(key,ciphertext)
```

### Gerar hash com argon2id

```python
hash_argon = hash_argon2id(key,password)
```

### Verificar hash argon2id

```python
hash_argon2id_verify(hash_argon, key,password)
```

## Licença

Este projeto está licenciado sob a Licença GPL-3.0. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir um issue.

## Autor

RAFAEL PERAZZO
