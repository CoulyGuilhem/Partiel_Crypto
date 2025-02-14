from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import argparse
import os

from AES_CBC import encrypt_aes_cbc, decrypt_aes_cbc
from AES_GCM import encrypt_aes_gcm, decrypt_aes_gcm


def save_key(key, filename="aes_key.txt"):
    with open(filename, "wb") as f:
        f.write(base64.b64encode(key))


def load_key(filename="aes_key.txt"):
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            return base64.b64decode(f.read())
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AES-CBC & AES-GCM Encryption/Decryption")
    parser.add_argument("mode", choices=["encrypt_cbc", "decrypt_cbc", "encrypt_gcm", "decrypt_gcm"],
                        help="Mode: encrypt_cbc, decrypt_cbc, encrypt_gcm, or decrypt_gcm")
    parser.add_argument("message", help="Message to encrypt or decrypt")
    args = parser.parse_args()

    if "encrypt" in args.mode:
        key = get_random_bytes(32)  # Clé AES de 256 bits
        save_key(key)
        if args.mode == "encrypt_cbc":
            encrypted_message = encrypt_aes_cbc(args.message, key)
        else:
            encrypted_message = encrypt_aes_gcm(args.message, key)
        print(f"Message chiffré : {encrypted_message}")
        print("Clé sauvegardée dans aes_key.txt")
    elif "decrypt" in args.mode:
        key = load_key()
        if key is None:
            print("Erreur : aucune clé trouvée. Assurez-vous d'avoir chiffré un message auparavant.")
        else:
            try:
                if args.mode == "decrypt_cbc":
                    decrypted_message = decrypt_aes_cbc(args.message, key)
                else:
                    decrypted_message = decrypt_aes_gcm(args.message, key)
                print(f"Message déchiffré : {decrypted_message}")
            except ValueError:
                print("Erreur : déchiffrement invalide ou message altéré.")