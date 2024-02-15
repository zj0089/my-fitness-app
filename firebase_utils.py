import firebase_admin
from firebase_admin import credentials, initialize_app


def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate("credentials.json")
        initialize_app(
            cred,
            {"databaseURL": "https://my-fitness-app-2024-default-rtdb.firebaseio.com/"},
            name="my-fitness-app-2024",
        )


# This function will be called to initialize Firebase
initialize_firebase()
