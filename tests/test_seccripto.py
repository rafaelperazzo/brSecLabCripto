'''
Automated tests for the SecCripto module.
'''
import secrets
from brseclabcripto.cripto3 import SecCripto

def test_aes_gcm_encrypt_decrypt():
    '''
    Test the AES GCM encryption and decryption functions.
    1. Encrypt a known plaintext with a known key.
    2. Check that the ciphertext is not equal to the plaintext.
    3. Check that the ciphertext is not empty.
    4. Decrypt the ciphertext.
    5. Check that the decrypted plaintext is equal to the original plaintext.
    '''
    # Test with a known plaintext and key
    key = secrets.token_bytes(32)  # 32 bytes key for AES-256
    plaintext = 'This is a test.'
    sec_cripto = SecCripto(key)
    ciphertext = sec_cripto.aes_gcm_encrypt(plaintext)
    # Check that the ciphertext is not equal to the plaintext
    assert ciphertext != plaintext
    assert len(ciphertext) > 0
    # Decrypt the ciphertext
    decrypted_plaintext = sec_cripto.aes_gcm_decrypt(ciphertext)
    # Check that the decrypted plaintext is equal to the original plaintext
    assert decrypted_plaintext == plaintext

def test_argon2():
    '''
    Test the Argon2 hashing and verification functions.
    1. Hash a known password with a known salt.
    2. Check that the hash is not empty.
    3. Verify the hash with the correct password.
    4. Verify the hash with an incorrect password.
    '''
    # Test with a known password and salt
    password = 'password123'
    salt = secrets.token_bytes(32)
    sec_cripto = SecCripto(salt)
    hash_argon = sec_cripto.hash_argon2id(password)
    # Check that the hash is not empty
    assert len(hash_argon) > 0
    # Verify the hash with the correct password
    assert sec_cripto.hash_argon2id_verify(hash_argon, password) is True
    # Verify the hash with an incorrect password
    assert sec_cripto.hash_argon2id_verify(hash_argon, 'wrongpassword') is False

def test_hmac():
    '''
    Test the HMAC functions.
    1. Create a known key and message.
    2. Generate an HMAC for the message.
    3. Verify the HMAC with the correct message.
    4. Verify the HMAC with an incorrect message.
    '''
    # Test with a known key and message
    key = secrets.token_bytes(32)
    message = 'This is a test.'
    sec_cripto = SecCripto(key)
    hmac_value = sec_cripto.hash_hmac(message)
    # Check that the HMAC is not empty
    assert len(hmac_value) > 0
    # Verify the HMAC with the correct message
    assert sec_cripto.hash_hmac_verify(message, hmac_value) is True
    # Verify the HMAC with an incorrect message
    assert sec_cripto.hash_hmac_verify('wrongmessage', hmac_value) is False
    # Verify the HMAC with an incorrect HMAC value
    assert sec_cripto.hash_hmac_verify(message, 'wronghmac') is False
    
def test_hash_sha256():
    '''
    Test the SHA256 hashing function.
    1. Hash a known message.
    2. Check that the hash is not empty.
    3. Verify the hash with the correct message.
    4. Verify the hash with an incorrect message.
    '''
    key = secrets.token_bytes(32)
    # Test with a known message
    message = 'This is a test.'
    sec_cripto = SecCripto(key)
    hash_value = sec_cripto.sha256(message)
    # Check that the hash is not empty
    assert len(hash_value) > 0
    # Verify the hash with the correct message
    assert sec_cripto.sha256_verify(message, hash_value) is True
    # Verify the hash with an incorrect message
    assert sec_cripto.sha256_verify('wrongmessage', hash_value) is False
    # Verify the hash with an incorrect hash value
    assert sec_cripto.sha256_verify(message, 'wronghash') is False
    # Verify the hash with an empty message
    assert sec_cripto.sha256_verify('', hash_value) is False
    # Verify the hash with an empty hash value
    assert sec_cripto.sha256_verify(message, '') is False
    # Verify the hash with an empty message and hash value
    assert sec_cripto.sha256_verify('', '') is False
    