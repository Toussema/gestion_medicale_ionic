from app import app, medecins, bcrypt
with app.app_context():
    medecins.insert_one({
        "name": "Mohamed",
        "sexe": "M",
        "etab": "CABINET MEDICAL INDIVIDUEL",
        "specialite": "UROLOGIE",
        "faculte": "Faculté de médecine de Tunis",
        "adresse": "RUE M'HAMED CHAABOOUNI OLFA PLACE ESC G SFAX",
        "tel": 74406601,
        "gsm": "28282828",
        "email": "exemple.medecin@gmail.com",
        "password": bcrypt.generate_password_hash("motdepasse").decode('utf-8'),
        "role": "medecin"
    })