from flask import Flask
from flask_pymongo import PyMongo
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()  # Lädt die Umgebungsvariablen aus der .env-Datei

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI") + "&ssl=true"
mongo = PyMongo(app)  # Initialisiert die Verbindung
print(f"Mongo URI: {os.getenv('MONGO_URI')}")
client = MongoClient('mongodb+srv://floki:FLOKI123@taxinovak.dmqd4.mongodb.net/')
print(client.list_database_names())