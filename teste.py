from pymongo import MongoClient
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

# Conexão com o MongoDB Atlas
client = MongoClient(
    'mongodb+srv://fyabiko:batata@cluster0.2hx4l.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client['chat_db']  # Nome do banco de dados
messages_collection = db['messages']  # Nome da coleção


# Função para gerar uma chave a partir de uma senha usando PBKDF2
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


# Função para cifrar uma mensagem
def cypher_message(message: str, password: str, salt: bytes):
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message


# Função para decifrar uma mensagem
def decrypt_message(encrypted_message: bytes, password: str, salt: bytes):
    key = generate_key(password, salt)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message


# Função para inserir uma mensagem no MongoDB (com criptografia)
def insert_message(sender: str, receiver: str, message: str, password: str):
    salt = os.urandom(16)  # Gera um novo salt para cada mensagem
    encrypted_message = cypher_message(message, password, salt)
    message_data = {
        'sender': sender,
        'receiver': receiver,
        'message': encrypted_message,
        'salt': salt
    }
    messages_collection.insert_one(message_data)
    print(f"Mensagem de {sender} para {receiver} armazenada com sucesso.")


# Função para buscar mensagens de um usuario (com descriptografia)

def get_messages_for_user(receiver: str, password: str):
    messages = messages_collection.find({'receiver': receiver})

    # Verifica se há mensagens (convertendo o cursor em uma lista)
    messages_list = list(messages)
    if len(messages_list) == 0:
        print("Nenhuma mensagem encontrada para esse destinatário.")
        return

    # Itera  tenta descriptografar as mensagens
    for msg in messages_list:
        try:
            decrypted_message = decrypt_message(msg['message'], password, msg['salt'])
            print(f"De {msg['sender']} para {msg['receiver']}: {decrypted_message}")
        except Exception as e:
            print(f"Erro ao descriptografar a mensagem de {msg['sender']}: {e}")


# Função para decifrar uma mensagem (com tratamento de erro)
def decrypt_message(encrypted_message: bytes, password: str, salt: bytes):
    try:
        key = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        raise ValueError("Erro na descriptografia. Verifique se a senha está correta.")


# Modelo no terminal
if __name__ == "__main__":
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
            get_messages_for_user(receiver, password)

        elif option == '3':
            print("Saindo...")
            break

        else:
            print("Opção invalida")

