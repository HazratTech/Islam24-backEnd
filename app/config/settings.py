import os
from dotenv import load_dotenv
from firebase_admin import credentials, firestore, storage, initialize_app

load_dotenv()

cred = credentials.Certificate(os.getenv("CERTIFICATE"))
firebase_app  = initialize_app(cred, {'storageBucket': os.getenv("APP_NAME")})

# Firestore and Storage clients
db = firestore.client()
bucket = storage.bucket()
