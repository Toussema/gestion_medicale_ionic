from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from bson.objectid import ObjectId
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/login": {"origins": "http://localhost:8100", "supports_credentials": True}})  # Autoriser uniquement les requêtes depuis http://localhost:8100

# Configuration de la base MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/medical_app"
mongo = PyMongo(app)
try:
    mongo.cx.server_info()  # Vérifie la connexion à MongoDB
    print("✅ Connexion à MongoDB réussie")
except Exception as e:
    print(f"❌ Erreur de connexion à MongoDB : {e}")

app.config["JWT_SECRET_KEY"] = "secret_key_super_securisee"  # Remplace par une clé forte
jwt = JWTManager(app)

bcrypt = Bcrypt(app)

patients = mongo.db.patient  # Collection des patients
medecins = mongo.db.medecin  # Collection des médecins
rendezvous = mongo.db.rendezvous  # Collection des rendez-vous

# Route d'inscription (seuls les patients peuvent s'inscrire)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data.get("email") or not data.get("password") or not data.get("name"):
        return jsonify({"message": "Nom complet, email et mot de passe requis"}), 400

    if patients.find_one({"email": data["email"]}) or medecins.find_one({"email": data["email"]}):
        return jsonify({"message": "Utilisateur déjà existant"}), 400

    hashed_pw = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    patient_data = {
        "name": data["name"],  # ✅ Stocker le nom complet
        "email": data["email"],
        "password": hashed_pw,
        "role": "patient"
    }
    patients.insert_one(patient_data)
    return jsonify({"message": "Inscription réussie"}), 201

# Route de connexion (patients et médecins)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    print("Données reçues :", data)  # Debugging

    user = patients.find_one({"email": data["email"]}) or medecins.find_one({"email": data["email"]})

    if not user:
        return jsonify({"message": "Email ou mot de passe incorrect"}), 401

    if not bcrypt.check_password_hash(user["password"], data["password"]):
        return jsonify({"message": "Email ou mot de passe incorrect"}), 401
    # Déterminer le nom complet en fonction du rôle
    if user["role"] == "patient":
        full_name = user.get("name", "Utilisateur")  # Utiliser "name" pour les patients
    else:
        # Utiliser "nom" et "prenom" pour les médecins
        full_name = f"{user.get('nom', '')} {user.get('prenom', '')}".strip()
        if not full_name:  # Si aucun nom n'est trouvé
            full_name = "Médecin"

    access_token = create_access_token(identity={"email": user["email"], "role": user["role"]})

    return jsonify({
        "message": "Connexion réussie",
        "token": access_token,
        "user": {
            "name": user["name"],  # ✅ Envoyer le nom complet
            "email": user["email"],
            "role": user["role"]
        }
    }), 200
    
    
    
# Récupérer la liste des médecins
@app.route('/medecins', methods=['GET'])
def get_medecins():
    medecins_list = list(medecins.find({}, {"password": 0}))
    for medecin in medecins_list:
        medecin["_id"] = str(medecin["_id"])
    return jsonify(medecins_list), 200

# Récupérer les détails d'un médecin
@app.route('/medecins/<id>', methods=['GET'])
def get_medecin(id):
    medecin = medecins.find_one({"_id": ObjectId(id)}, {"password": 0})
    if medecin:
        medecin["_id"] = str(medecin["_id"])
        return jsonify(medecin), 200
    else:
        return jsonify({"message": "Médecin non trouvé"}), 404

# Route pour créer un rendez-vous (protégée par JWT)
@app.route('/rendezvous', methods=['POST'])
@jwt_required()  # Nécessite un token JWT valide
def create_rendezvous():
    data = request.json
    current_user = get_jwt_identity()  # Récupère l'utilisateur actuel à partir du token JWT

    if not data.get("medecinId") or not data.get("date") or not data.get("heure"):
        return jsonify({"message": "Tous les champs sont requis"}), 400

    # Vérifier que la date et l'heure sont valides
    try:
        datetime.strptime(data["date"], "%Y-%m-%d")  # Format de date attendu : YYYY-MM-DD
        datetime.strptime(data["heure"], "%H:%M")  # Format d'heure attendu : HH:MM
    except ValueError:
        return jsonify({"message": "Date ou heure invalide"}), 400

    # Vérifier les conflits de rendez-vous
    existing_rendezvous = rendezvous.find_one({
        "medecinId": data["medecinId"],
        "date": data["date"],
        "heure": data["heure"]
    })
    if existing_rendezvous:
        return jsonify({"message": "Un rendez-vous existe déjà à cette date et heure"}), 400

    rendezvous_data = {
        "patientId": current_user["email"],  # Utiliser l'email du patient comme identifiant
        "medecinId": data["medecinId"],
        "date": data["date"],
        "heure": data["heure"],
        "status": "en_attente"  # Statut par défaut
    }

    # Insérer le rendez-vous dans la collection
    rendezvous_id = rendezvous.insert_one(rendezvous_data).inserted_id
    return jsonify({"message": "Rendez-vous créé avec succès", "id": str(rendezvous_id)}), 201

# Route pour récupérer les rendez-vous d'un patient (protégée par JWT)
@app.route('/rendezvous/patient', methods=['GET'])
@jwt_required()  # Nécessite un token JWT valide
def get_rendezvous_by_patient():
    current_user = get_jwt_identity()  # Récupère l'utilisateur actuel à partir du token JWT
    patient_rendezvous = list(rendezvous.find({"patientId": current_user["email"]}))
    for rdv in patient_rendezvous:
        rdv["_id"] = str(rdv["_id"])  # Convertir ObjectId en string
    return jsonify(patient_rendezvous), 200

# Route pour récupérer les rendez-vous d'un médecin (protégée par JWT)
@app.route('/rendezvous/medecin', methods=['GET'])
@jwt_required()  # Nécessite un token JWT valide
def get_rendezvous_by_medecin():
    current_user = get_jwt_identity()  # Récupère l'utilisateur actuel à partir du token JWT
    medecin_rendezvous = list(rendezvous.find({"medecinId": current_user["email"]}))
    for rdv in medecin_rendezvous:
        rdv["_id"] = str(rdv["_id"])  # Convertir ObjectId en string
    return jsonify(medecin_rendezvous), 200

@app.route('/')
def home():
    return jsonify({"message": "Serveur Flask en marche"}), 200

if __name__ == '__main__':
    app.run(debug=True)