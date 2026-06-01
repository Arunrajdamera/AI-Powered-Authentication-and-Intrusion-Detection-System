from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from hashlib import sha256


def aes_encrypt(message):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return key, cipher.nonce, ciphertext


def aes_decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()


def rsa_demo(message):
    key = RSA.generate(2048)
    public_key = key.publickey()

    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(message.encode())

    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(encrypted)

    return encrypted, decrypted.decode()


def hash_message(message):
    return sha256(message.encode()).hexdigest()


message = input("Enter Message: ")

key, nonce, encrypted = aes_encrypt(message)
print("\nAES Encrypted:", encrypted)

decrypted = aes_decrypt(key, nonce, encrypted)
print("AES Decrypted:", decrypted)

rsa_enc, rsa_dec = rsa_demo(message)
print("\nRSA Decrypted:", rsa_dec)

print("\nSHA256 Hash:")
print(hash_message(message))
