# Partiel cryptographie

1) Utilisation:

### Encrypt : 
Commandes :

CBC: python .\main.py encrypt_cbc <mon_message>

GCM: python .\main.py encrypt_gcm <mon_message>

Génère un fichier aes_key.txt qui contient la clé de chiffrement
Ecrit dans la console le message crypté

### Decrypt :
Commandes : 

CBC: python .\main.py decrypt_cbc <mon_message_crypté>

GCM: python .\main.py decrypt_gcm <mon_message_crypté>

Renvoie le message décrypté dans la console.