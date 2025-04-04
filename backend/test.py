from app import app, medecins, bcrypt
with app.app_context():
    medecins.insert_one({
        "name": "Salah Abdelhay",
        "sexe": "M",
        "etab": "CABINET MEDICAL INDIVIDUEL",
        "specialite": "Cardiologe",
        "faculte": "Faculté de médecine de Sfax",
        "adresse": "Rue de la liberté, Tunis",
        "tel": 75200300,
        "gsm": "27200300",
        "email": "exemple.medecin1@gmail.com",
        "password": bcrypt.generate_password_hash("motdepasse2").decode('utf-8'),
        "role": "medecin"
    })
# motdepasse, motdepasse2