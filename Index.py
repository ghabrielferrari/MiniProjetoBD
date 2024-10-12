import base64
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import hashlib

# Conexão com o MongoDB
client = MongoClient("mongodb+srv://gabriel:gabriel123@consultas.bpjd6.mongodb.net/?retryWrites=true&w=majority")
db = client['Consultas']
messages_collection = db['messages']

def generate_key(password, salt):
    """Gera uma chave a partir da senha e salt usando SHA-256."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def encrypt_message(message, password):
    """Cifra a mensagem usando AES CBC."""
    salt = os.urandom(16)
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return {
        'message': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.iv).decode(),
        'salt': base64.b64encode(salt).decode()
    }

def decrypt_message(encrypted_data, password):
    """Decifra a mensagem cifrada."""
    try:
        key = generate_key(password, base64.b64decode(encrypted_data['salt']))
        cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(encrypted_data['nonce']))
        return unpad(cipher.decrypt(base64.b64decode(encrypted_data['message'])), AES.block_size).decode()
    except:
        return None

def insert_message(from_user, to_user, message, password):
    """Insere uma nova mensagem no banco de dados."""
    encrypted_data = encrypt_message(message, password)
    messages_collection.insert_one({'from': from_user, 'to': to_user, **encrypted_data})
    print("Mensagem de {} para {} inserida.".format(from_user, to_user))

def fetch_messages(to_user, password):
    """Busca mensagens destinadas a um usuário e tenta decifrá-las."""
    for message in messages_collection.find({'to': to_user}):
        decrypted = decrypt_message(message, password)
        print(decrypted if decrypted else "Erro ao decifrar a mensagem.")

# Exemplo de uso
if __name__ == "__main__":
    print("Conectado ao MongoDB!")
    while True:
        print("\n1. Enviar mensagem")
        print("2. Ver mensagens")
        print("3. Sair")
        option = input("Escolha uma opção: ")

        if option == '1':
            sender = input("De: ")
            receiver = input("Para: ")
            message = input("Mensagem: ")
            password = input("Senha: ")
            insert_message(sender, receiver, message, password)

        elif option == '2':
            receiver = input("Ver mensagens de: ")
            password = input("Senha: ")
            fetch_messages(receiver, password)

        elif option == '3':
            print("Saindo...")
            break

        else:
            print("Opção inválida")