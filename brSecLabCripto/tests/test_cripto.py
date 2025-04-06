'''
Automated tests for the cripto module.
'''
import secrets
from brseclabcripto.cripto2 import aes_gcm_encrypt, aes_gcm_decrypt, gpg_encrypt, gpg_decrypt, hash_argon2id, hash_argon2id_verify
from brseclabcripto.cripto2 import hash_hmac, hash_hmac_verify, sha256, sha256_verify

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
    key = secrets.token_bytes(32) # 32 bytes key for AES-256
    plaintext = 'This is a test.'
    ciphertext = aes_gcm_encrypt(key, plaintext)
    # Check that the ciphertext is not equal to the plaintext
    assert ciphertext != plaintext
    assert len(ciphertext) > 0
    # Decrypt the ciphertext
    decrypted_plaintext = aes_gcm_decrypt(key, ciphertext)
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
    hash_argon = hash_argon2id(salt,password)
    # Check that the hash is not empty
    assert len(hash_argon) > 0
    # Verify the hash with the correct password
    assert hash_argon2id_verify(hash_argon, salt,password) is True
    # Verify the hash with an incorrect password
    assert hash_argon2id_verify(hash_argon, salt,'wrondpassword') is False
    
def test_gpg_encrypt_decrypt():
    '''
    Test the GPG encryption and decryption functions.
    1. Encrypt a known plaintext with a known key.
    2. Check that the ciphertext is not equal to the plaintext.
    3. Check that the ciphertext is not empty.
    4. Decrypt the ciphertext.
    5. Check that the decrypted plaintext is equal to the original plaintext.
    '''
    # Test with a known plaintext and key
    key = '1234567890123456789012345678901234567890123456789012345678901234567890'
    plaintext = 'This is a test.'
    ciphertext = gpg_encrypt(key, plaintext)
    # Check that the ciphertext is not equal to the plaintext
    assert ciphertext != plaintext
    assert len(ciphertext) > 0
    # Decrypt the ciphertext
    decrypted_plaintext = gpg_decrypt(key, ciphertext)
    # Check that the decrypted plaintext is equal to the original plaintext
    assert decrypted_plaintext == plaintext

def test_hmac():
    '''
    Test the HMAC functions.
    1. Create a known key and message.
    2. Generate an HMAC for the message.
    3. Verify the HMAC with the correct message.
    4. Verify the HMAC with an incorrect message.
    '''
    # Test with a known key and message
    key = secrets.token_bytes(32) # 32 bytes key for HMAC
    message = 'This is a test.'
    hmac_value = hash_hmac(key, message)
    # Verify the HMAC with the correct message
    assert hash_hmac_verify(key, message,hmac_value) is True
    # Verify the HMAC with an incorrect message
    assert hash_hmac_verify(key, 'wrongmessage',hmac_value) is False

def test_hash_sha256():
    '''
    Test the SHA256 hashing function.
    1. Hash a known message.
    2. Check that the hash is not empty.
    3. Verify the hash with the correct message.
    4. Verify the hash with an incorrect message.
    '''
    # Test with a known message
    message = 'This is a test.'
    hash_value = sha256(message)
    # Check that the hash is not empty
    assert len(hash_value) > 0
    # Verify the hash with the correct message
    assert sha256_verify(message, hash_value) is True
    # Verify the hash with an incorrect message
    assert sha256_verify('wrongmessage', hash_value) is False