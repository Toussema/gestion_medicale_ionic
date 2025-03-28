from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from bson.objectid import ObjectId
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:8100", "supports_credentials": True}})

# Configuration de la base MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/medical_app"
mongo = PyMongo(app)
try:
    mongo.cx.server_info()
    print("✅ Connexion à MongoDB réussie")
except Exception as e:
    print(f"❌ Erreur de connexion à MongoDB : {e}")

app.config["JWT_SECRET_KEY"] = "secret_key_super_securisee"
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

patients = mongo.db.patient
medecins = mongo.db.medecin
disponibilites = mongo.db.disponibilite
rendezvous = mongo.db.rendezvous

# Route d'inscription (patients)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data.get("email") or not data.get("password") or not data.get("name"):
        return jsonify({"message": "Nom complet, email et mot de passe requis"}), 400

    if patients.find_one({"email": data["email"]}) or medecins.find_one({"email": data["email"]}):
        return jsonify({"message": "Utilisateur déjà existant"}), 400

    hashed_pw = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    patient_data = {
        "name": data["name"],
        "email": data["email"],
        "password": hashed_pw,
        "role": "patient"
    }
    patients.insert_one(patient_data)
    return jsonify({"message": "Inscription réussie"}), 201

# Route de connexion
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"message": "Email et mot de passe requis"}), 400

        user = patients.find_one({"email": data["email"]}) or medecins.find_one({"email": data["email"]})
        if not user:
            return jsonify({"message": "Identifiants incorrects"}), 401

        if not bcrypt.check_password_hash(user["password"], data["password"]):
            return jsonify({"message": "Identifiants incorrects"}), 401

        # Gestion du nom selon le rôle
        full_name = user["name"] if user["role"] == "patient" else user.get("name", "Médecin")

        token_data = {
            "email": user["email"],
            "role": user["role"],
            "id": str(user["_id"])
        }
        access_token = create_access_token(identity=token_data)

        # Réponse avec toutes les infos nécessaires
        response_data = {
            "message": "Connexion réussie",
            "token": access_token,
            "user": {
                "id": str(user["_id"]),
                "name": full_name,
                "email": user["email"],
                "role": user["role"]
            }
        }

        # Ajout des infos supplémentaires pour les médecins
        if user["role"] == "medecin":
            response_data["user"].update({
                "specialite": user.get("specialite", ""),
                "adresse": user.get("adresse", ""),
                "tel": user.get("tel", ""),
                "gsm": user.get("gsm", "")
            })

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Erreur lors de la connexion : {str(e)}")
        return jsonify({"message": "Erreur interne du serveur"}), 500

# Routes pour les médecins
@app.route('/medecins', methods=['GET'])
def get_medecins():
    medecins_list = list(medecins.find({}, {"password": 0}))
    for medecin in medecins_list:
        medecin["_id"] = str(medecin["_id"])
    return jsonify(medecins_list), 200

@app.route('/medecins/<id>', methods=['GET'])
def get_medecin(id):
    medecin = medecins.find_one({"_id": ObjectId(id)}, {"password": 0})
    if medecin:
        medecin["_id"] = str(medecin["_id"])
        return jsonify(medecin), 200
    return jsonify({"message": "Médecin non trouvé"}), 404

@app.route('/medecins/disponibilites', methods=['GET', 'POST'])
@jwt_required()
def gestion_disponibilites():  # Renommez la fonction pour refléter les deux actions
    current_user = get_jwt_identity()
    if current_user["role"] != "medecin":
        return jsonify({"message": "Accès refusé"}), 403

    medecin_id = ObjectId(current_user["id"])

    if request.method == 'POST':
        return save_disponibilites(medecin_id)  # Nouvelle méthode pour POST
    else:
        return get_disponibilites(medecin_id)  # Méthode existante pour GET

def get_disponibilites(medecin_id):
    """Récupère les disponibilités"""
    doc = mongo.db.disponibilite.find_one({"medecinId": medecin_id})
    
    if not doc:
        # Retourne une structure vide avec tous les jours
        jours_vides = {
            "lundi": [], "mardi": [], "mercredi": [], 
            "jeudi": [], "vendredi": [], "samedi": []
        }
        return jsonify(jours_vides), 200
    
    return jsonify(doc.get("horaires", {})), 200

def save_disponibilites(medecin_id):
    """Sauvegarde les nouvelles disponibilités"""
    try:
        data = request.get_json()
        
        # Validation minimale
        if not data or not isinstance(data.get("horaires"), dict):
            return jsonify({"message": "Le champ 'horaires' (object) est requis"}), 422

        # Validation des créneaux
        for jour, creneaux in data["horaires"].items():
            if not isinstance(creneaux, list):
                return jsonify({"message": f"Le jour '{jour}' doit contenir un tableau de créneaux"}), 422
                
            for creneau in creneaux:
                try:
                    datetime.strptime(creneau["debut"], "%H:%M")
                    datetime.strptime(creneau["fin"], "%H:%M")
                except (ValueError, KeyError):
                    return jsonify({"message": f"Format HH:MM invalide pour {jour}"}), 422

        # Upsert dans MongoDB
        mongo.db.disponiblite.update_one(
            {"medecinId": medecin_id},
            {"$set": {"horaires": data["horaires"]}},
            upsert=True
        )
        
        return jsonify({"message": "Disponibilités mises à jour"}), 200

    except Exception as e:
        print(f"Erreur: {str(e)}")
        return jsonify({"message": "Erreur interne du serveur"}), 500

# Nouvelle route pour les rendez-vous
@app.route('/rendezvous', methods=['GET'])
@jwt_required()
def get_rendezvous():
    current_user = get_jwt_identity()
    
    if current_user["role"] == "medecin":
        rdvs = list(rendezvous.find({"medecinId": current_user["email"]}))
    else:
        rdvs = list(rendezvous.find({"patientId": current_user["email"]}))

    for rdv in rdvs:
        rdv["_id"] = str(rdv["_id"])
    
    return jsonify(rdvs), 200

@app.route('/')
def home():
    return jsonify({"message": "Serveur Flask en marche"}), 200

if __name__ == '__main__':
    app.run(debug=True)