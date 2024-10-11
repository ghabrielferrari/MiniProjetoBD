import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# Conexão com o MongoDB
uri = "mongodb+srv://gabriel:gabriel123@consultas.bpjd6.mongodb.net/?retryWrites=true&w=majority&appName=Consultas"
client = MongoClient(uri, server_api=ServerApi('1'))

# Testar a conexão com o MongoDB
try:
    client.admin.command('ping')
    print("Conexão bem-sucedida com MongoDB!")
except Exception as e:
    print(e)

# Escolhe a base de dados e coleção
db = client['Consultas']
messages_collection = db['messages']