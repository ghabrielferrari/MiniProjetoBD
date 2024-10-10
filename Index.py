import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import hashlib

# Conexão com MongoDB
uri = "mongodb+srv://gabriel:gabriel123@consultas.bpjd6.mongodb.net/?retryWrites=true&w=majority&appName=Consultas"
client = MongoClient(uri, server_api=ServerApi('1'))

# Escolhe a base de dados e coleção
db = client['Consultas']
messages_collection = db['messages']

# Função para gerar chave secreta a partir de uma senha
def generate_key(password, salt):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key

# Função para criptografar mensagem
def encrypt_message(message, password):
    salt = get_random_bytes(16)
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return {
        'message': base64.b64encode(encrypted_message).decode('utf-8'),
        'nonce': base64.b64encode(iv).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }

# Função para descriptografar mensagem
def decrypt_message(encrypted_data, password):
    try:
        # Verifica se a mensagem possui os campos necessários
        if 'salt' not in encrypted_data or 'nonce' not in encrypted_data or 'message' not in encrypted_data:
            print("Erro: Mensagem sem informações necessárias para decifrar.")
            return None

        salt = base64.b64decode(encrypted_data['salt'])
        iv = base64.b64decode(encrypted_data['nonce'])
        encrypted_message = base64.b64decode(encrypted_data['message'])
        key = generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        return decrypted_message.decode('utf-8')

    except (KeyError, ValueError, TypeError, base64.binascii.Error) as e:
        print(f"Erro ao decifrar a mensagem: {str(e)}")
        return None

# Função para inserir mensagem no banco de dados
def insert_message(from_user, to_user, message, password):
    encrypted_data = encrypt_message(message, password)
    encrypted_data['from'] = from_user
    encrypted_data['to'] = to_user
    messages_collection.insert_one(encrypted_data)
    print(f"Mensagem de {from_user} para {to_user} inserida com sucesso.")

# Função para buscar e decifrar mensagens de um destinatário
def fetch_messages(to_user, password):
    messages = messages_collection.find({'to': to_user})
    for message in messages:
        decrypted_message = decrypt_message(message, password)
        if decrypted_message:
            print(decrypted_message)

# Main
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

# Insere mensagem de Alice para Bob
password = input("Digite a chave secreta para o chat: ")
insert_message('Alice', 'Bob', "Olá Bob, fez o dever de casa?", password)

# Busca mensagens para Bob
print("\nMensagens para Bob:")
fetch_messages('Bob', password)