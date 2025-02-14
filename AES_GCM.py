from Crypto.Cipher import AES
import base64

def encrypt_aes_gcm(plain_text, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def decrypt_aes_gcm(encrypted_text, key):
    encrypted_bytes = base64.b64decode(encrypted_text)
    nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()