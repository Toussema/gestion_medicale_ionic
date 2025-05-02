from app import app, medecins, bcrypt
with app.app_context():
    medecins.insert_one({
        "name": "Anas Barrak",
        "sexe": "M",
        "etab": "CABINET MEDICAL INDIVIDUEL",
        "specialite": "STOMATOLOGIE",
        "faculte": "Faculté de médecine de Sousse",
        "adresse": "6, RUE LAGHA",
        "tel": 72276829,
        "gsm": "56505050",
        "email": "exemple.medecin3@gmail.com",
        "password": bcrypt.generate_password_hash("motdepasse3").decode('utf-8'),
        "role": "medecin",
        "gouvernorat": "Tunis", 
        "ville": "El Kram"
    })
# motdepasse, motdepasse2