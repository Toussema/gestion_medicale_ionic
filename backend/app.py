from flask import Flask, request, jsonify, send_file
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import sqlite3
import io

app = Flask(__name__)
# Configuration CORS explicite
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:8100"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True
    }
})


# Gestion explicite des requêtes OPTIONS
@app.route('/user/profile', methods=['OPTIONS'])
def options_user_profile():
    response = jsonify({"message": "CORS preflight OK"})
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:8100"
    response.headers["Access-Control-Allow-Methods"] = "GET, PUT, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response, 200


# Configuration de la base MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/medical_app"
mongo = PyMongo(app)
try:
    mongo.cx.server_info()
    print("✅ Connexion à MongoDB réussie")
except Exception as e:
    print(f"❌ Erreur de connexion à MongoDB : {e}")

# Configuration JWT
app.config["JWT_SECRET_KEY"] = "secret_key_super_securisee"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)  # Durée de vie de 2 heure
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Collections MongoDB
patients = mongo.db.patient
medecins = mongo.db.medecin
disponibilites = mongo.db.disponibilite
rendezvous = mongo.db.rendezvous
notifications = mongo.db.notifications  # Nouvelle collection

# Fonction pour obtenir une connexion SQLite
def get_sqlite_connection():
    conn = sqlite3.connect('documents.db')
    conn.row_factory = sqlite3.Row  # Retourne les lignes sous forme de dictionnaires
    return conn

# Création de la table au démarrage
def init_sqlite_db():
    with get_sqlite_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id TEXT NOT NULL,
                medecin_id TEXT NOT NULL,
                titre TEXT NOT NULL,
                fichier BLOB NOT NULL,
                date_envoi DATETIME DEFAULT CURRENT_TIMESTAMP,
                statut TEXT DEFAULT 'Non consulté',
                remarques TEXT
            )
        ''')
        conn.commit()
        print("Table 'documents' créée ou déjà existante.")

# Fonction pour créer une notification (ajoutée ici)
def create_notification(user_id, message, type):
    notification = {
        "user_id": user_id,
        "message": message,
        "type": type,
        "created_at": datetime.utcnow(),
        "read": False
    }
    notifications.insert_one(notification)

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

        full_name = user["name"] if user["role"] == "patient" else user.get("name", "Médecin")
        user_id = str(user["_id"])
        access_token = create_access_token(
            identity=user_id,
            additional_claims={"email": user["email"], "role": user["role"]}
        )

        response_data = {
            "message": "Connexion réussie",
            "token": access_token,
            "user": {
                "id": user_id,
                "name": full_name,
                "email": user["email"],
                "role": user["role"]
            }
        }
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

# Gestion des disponibilités
@app.route('/disponibilites', methods=['GET', 'POST'])
@jwt_required()
def manage_disponibilites():
    user_id = get_jwt_identity()
    claims = get_jwt()
    print(f"User_id: {user_id}, Role: {claims['role']}")
    
    if claims["role"] != "medecin":
        return jsonify({"message": "Accès réservé aux médecins"}), 403

    if request.method == 'GET':
        doc = disponibilites.find_one({"medecinId": user_id})
        default = {"lundi": [], "mardi": [], "mercredi": [], "jeudi": [], "vendredi": [], "samedi": []}
        return jsonify(doc["horaires"] if doc else default), 200

    if request.method == 'POST':
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify({"message": "Données invalides"}), 400
        disponibilites.update_one(
            {"medecinId": user_id},
            {"$set": {"horaires": data}},
            upsert=True
        )
        return jsonify({"message": "Disponibilités mises à jour"}), 200

# Nouvelle route pour récupérer la liste des médecins avec leurs disponibilités
@app.route('/medecins', methods=['GET'])
def get_medecins():
    try:
        medecins_list = list(medecins.find({}, {"password": 0}))
        result = []
        for medecin in medecins_list:
            medecin_id = str(medecin["_id"])
            dispo = disponibilites.find_one({"medecinId": medecin_id})
            default_dispo = {"lundi": [], "mardi": [], "mercredi": [], "jeudi": [], "vendredi": [], "samedi": []}
            medecin_data = {
                "id": medecin_id,
                "name": medecin.get("name", "Médecin"),
                "email": medecin["email"],
                "specialite": medecin.get("specialite", ""),
                "adresse": medecin.get("adresse", ""),
                "sexe": medecin.get("sexe", ""),
                "etab": medecin.get("etab", ""),
                "faculte": medecin.get("faculte", ""),
                "tel": medecin.get("tel", ""),
                "gsm": medecin.get("gsm", ""),
                "disponibilites": dispo["horaires"] if dispo else default_dispo
            }
            result.append(medecin_data)
        return jsonify(result), 200
    except Exception as e:
        print(f"Erreur lors de la récupération des médecins : {str(e)}")
        return jsonify({"message": "Erreur interne du serveur"}), 500
    
# Gestion des rendez-vous
@app.route('/rendezvous', methods=['GET', 'POST'])
@jwt_required()
def manage_rendezvous():
    user_id = get_jwt_identity()
    claims = get_jwt()
    user = patients.find_one({"_id": ObjectId(user_id)}) or medecins.find_one({"_id": ObjectId(user_id)})

    if request.method == 'GET':
        if claims["role"] == "medecin":
            rdvs = list(rendezvous.find({"medecinId": user_id}))
            result = []
            for rdv in rdvs:
                patient = patients.find_one({"_id": ObjectId(rdv["patientId"])})
                result.append({
                    "_id": str(rdv["_id"]),
                    "patientName": patient["name"] if patient else "Inconnu",
                    "patientEmail": patient["email"] if patient else "N/A",
                    "jour": rdv["jour"],
                    "debut": rdv["debut"],
                    "fin": rdv["fin"],
                    "statut": rdv["statut"]
                })
            return jsonify(result), 200
        else:
            rdvs = list(rendezvous.find({"patientId": user_id}))
            result = []
            for rdv in rdvs:
                medecin = medecins.find_one({"_id": ObjectId(rdv["medecinId"])})
                result.append({
                    "_id": str(rdv["_id"]),
                    "medecinName": medecin["name"] if medecin else "Inconnu",
                    "medecinSpecialite": medecin.get("specialite", "Généraliste") if medecin else "N/A",
                    "medecinAdresse": medecin.get("adresse", "") if medecin else "N/A",
                    "jour": rdv["jour"],
                    "debut": rdv["debut"],
                    "fin": rdv["fin"],
                    "statut": rdv["statut"]
                })
            return jsonify(result), 200

    if request.method == 'POST':
        data = request.get_json()
        if claims["role"] != "patient" or not all(k in data for k in ["medecinId", "jour", "debut", "fin"]):
            return jsonify({"message": "Données invalides ou accès refusé"}), 400
        rdv = {
            "medecinId": data["medecinId"],
            "patientId": user_id,
            "jour": data["jour"],
            "debut": data["debut"],
            "fin": data["fin"],
            "statut": "confirmé"
        }
        result = rendezvous.insert_one(rdv)
        # Notification pour le médecin
        medecin = medecins.find_one({"_id": ObjectId(data["medecinId"])})
        patient = patients.find_one({"_id": ObjectId(user_id)})
        if medecin and patient:
            create_notification(data["medecinId"], 
                              f"{patient['name']} a pris un rendez-vous le {data['jour']} de {data['debut']} à {data['fin']}.",
                              "rendezvous")
        return jsonify({"message": "Rendez-vous pris", "id": str(result.inserted_id)}), 201

@app.route('/rendezvous/<rdv_id>/annuler', methods=['POST'])
@jwt_required()
def annuler_rendezvous(rdv_id):
    user_id = get_jwt_identity()
    claims = get_jwt()
    rdv = rendezvous.find_one({"_id": ObjectId(rdv_id)})
    if not rdv or (rdv["patientId"] != user_id and rdv["medecinId"] != user_id):
        return jsonify({"message": "Rendez-vous non trouvé ou accès refusé"}), 404
    rendezvous.update_one({"_id": ObjectId(rdv_id)}, {"$set": {"statut": "annulé"}})
    
    # Notifications selon qui annule
    if claims["role"] == "patient":
        medecin = medecins.find_one({"_id": ObjectId(rdv["medecinId"])})
        patient = patients.find_one({"_id": ObjectId(user_id)})
        if medecin and patient:
            create_notification(rdv["medecinId"], 
                              f"{patient['name']} a annulé un rendez-vous le {rdv['jour']} de {rdv['debut']} à {rdv['fin']}.",
                              "rendezvous")
    else:  # Médecin
        patient = patients.find_one({"_id": ObjectId(rdv["patientId"])})
        medecin = medecins.find_one({"_id": ObjectId(user_id)})  # Récupérer le médecin ici
        if patient and medecin:
            create_notification(rdv["patientId"], 
                              f"Votre rendez-vous avec {medecin['name']} le {rdv['jour']} de {rdv['debut']} à {rdv['fin']} a été annulé.",
                              "rendezvous")
    return jsonify({"message": "Rendez-vous annulé"}), 200

# Nouvelles routes pour les documents (SQLite) avec notifications
@app.route('/documents/upload', methods=['POST'])
@jwt_required()
def upload_document():
    claims = get_jwt()
    if claims["role"] != "patient":
        return jsonify({"message": "Accès réservé aux patients"}), 403

    user_id = get_jwt_identity()
    if 'fichier' not in request.files or 'medecin_id' not in request.form or 'titre' not in request.form:
        return jsonify({'message': 'Champs manquants'}), 400

    fichier = request.files['fichier']
    medecin_id = request.form['medecin_id']
    titre = request.form['titre']
    fichier_data = fichier.read()

    with get_sqlite_connection() as conn:
        cursor = conn.execute(
            'INSERT INTO documents (patient_id, medecin_id, titre, fichier) VALUES (?, ?, ?, ?)',
            (user_id, medecin_id, titre, fichier_data)
        )
        conn.commit()
        doc_id = cursor.lastrowid
    # Notification pour le médecin
    medecin = medecins.find_one({"_id": ObjectId(medecin_id)})
    patient = patients.find_one({"_id": ObjectId(user_id)})
    if medecin and patient:
        create_notification(medecin_id, 
                          f"{patient['name']} vous a envoyé un document : {titre}.",
                          "document")
    return jsonify({'id': doc_id, 'message': 'Document envoyé avec succès'}), 201

@app.route('/documents/patient', methods=['GET'])
@jwt_required()
def get_patient_documents():
    claims = get_jwt()
    if claims["role"] != "patient":
        return jsonify({"message": "Accès réservé aux patients"}), 403

    user_id = get_jwt_identity()
    with get_sqlite_connection() as conn:
        cursor = conn.execute(
            'SELECT id, titre, date_envoi, statut, remarques FROM documents WHERE patient_id = ?',
            (user_id,)
        )
        docs = [dict(row) for row in cursor.fetchall()]
    return jsonify(docs), 200

@app.route('/documents/medecin', methods=['GET'])
@jwt_required()
def get_medecin_documents():
    claims = get_jwt()
    if claims["role"] != "medecin":
        return jsonify({"message": "Accès réservé aux médecins"}), 403

    user_id = get_jwt_identity()
    with get_sqlite_connection() as conn:
        cursor = conn.execute(
            'SELECT id, patient_id, titre, date_envoi, statut, remarques FROM documents WHERE medecin_id = ?',
            (user_id,)
        )
        docs = [dict(row) for row in cursor.fetchall()]
    return jsonify(docs), 200

@app.route('/documents/<int:doc_id>/download', methods=['GET'])
@jwt_required()
def download_document(doc_id):
    user_id = get_jwt_identity()
    claims = get_jwt()

    with get_sqlite_connection() as conn:
        cursor = conn.execute('SELECT fichier, titre, patient_id, medecin_id, statut FROM documents WHERE id = ?', (doc_id,))
        doc = cursor.fetchone()
        if not doc:
            return jsonify({'message': 'Document non trouvé'}), 404
        if doc['patient_id'] != user_id and doc['medecin_id'] != user_id:
            return jsonify({'message': 'Accès refusé'}), 403
        
        # Notification si le médecin consulte pour la première fois
        if claims["role"] == "medecin" and doc["statut"] == "Non consulté":
            patient = patients.find_one({"_id": ObjectId(doc["patient_id"])})
            if patient:
                create_notification(doc["patient_id"], 
                                  f"Votre document '{doc['titre']}' a été consulté par votre médecin.",
                                  "document")
            conn.execute('UPDATE documents SET statut = ? WHERE id = ?', ('Consulté', doc_id))
            conn.commit()

        return send_file(
            io.BytesIO(doc['fichier']),
            download_name=doc['titre'],
            as_attachment=True
        )

@app.route('/documents/<int:doc_id>/annotate', methods=['PUT'])
@jwt_required()
def annotate_document(doc_id):
    claims = get_jwt()
    if claims["role"] != "medecin":
        return jsonify({"message": "Accès réservé aux médecins"}), 403

    user_id = get_jwt_identity()
    remarques = request.json.get('remarques', '')
    
    with get_sqlite_connection() as conn:
        cursor = conn.execute(
            'UPDATE documents SET statut = ?, remarques = ? WHERE id = ? AND medecin_id = ?',
            ('Consulté', remarques, doc_id, user_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({'message': 'Document non trouvé ou accès refusé'}), 404
        
        # Notification pour le patient
        cursor = conn.execute('SELECT patient_id, titre FROM documents WHERE id = ?', (doc_id,))
        doc = cursor.fetchone()
        if doc:
            patient = patients.find_one({"_id": ObjectId(doc["patient_id"])})
            if patient:
                create_notification(doc["patient_id"], 
                                  f"Votre document '{doc['titre']}' a été annoté par votre médecin.",
                                  "document")
    
    return jsonify({'message': 'Document mis à jour'}), 200

# Nouvelle route pour récupérer les notifications
@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifs = list(notifications.find({"user_id": user_id}).sort("created_at", -1))
    result = [{"id": str(n["_id"]), "message": n["message"], "type": n["type"], "created_at": n["created_at"].isoformat(), "read": n["read"]} for n in notifs]
    return jsonify(result), 200

# Marquer une notification comme lue
@app.route('/notifications/<notif_id>/read', methods=['PUT'])
@jwt_required()
def mark_notification_read(notif_id):
    user_id = get_jwt_identity()
    result = notifications.update_one(
        {"_id": ObjectId(notif_id), "user_id": user_id},
        {"$set": {"read": True}}
    )
    if result.modified_count == 0:
        return jsonify({"message": "Notification non trouvée ou déjà lue"}), 404
    return jsonify({"message": "Notification marquée comme lue"}), 200


# Route pour récupérer le profil de l'utilisateur connecté
@app.route('/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user_id = get_jwt_identity()
    claims = get_jwt()
    print(f"GET /user/profile - User ID: {user_id}, Role: {claims['role']}")

    if claims["role"] == "medecin":
        user = medecins.find_one({"_id": ObjectId(user_id)}, {"password": 0})  # Exclure le mot de passe
        if not user:
            print("Médecin non trouvé")
            return jsonify({"message": "Utilisateur non trouvé"}), 404
        # Convertir ObjectId en string et s'assurer que tous les champs sont inclus
        user["_id"] = str(user["_id"])
        print(f"Profil médecin retourné: {user}")
        return jsonify(user), 200
    elif claims["role"] == "patient":
        user = patients.find_one({"_id": ObjectId(user_id)}, {"password": 0})
        if not user:
            print("Patient non trouvé")
            return jsonify({"message": "Utilisateur non trouvé"}), 404
        user["_id"] = str(user["_id"])
        print(f"Profil patient retourné: {user}")
        return jsonify(user), 200
    else:
        print("Rôle non reconnu")
        return jsonify({"message": "Rôle non reconnu"}), 400

# Route pour mettre à jour le profil de l'utilisateur connecté
@app.route('/user/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    user_id = get_jwt_identity()
    claims = get_jwt()
    data = request.get_json()

    if not data:
        return jsonify({"message": "Aucune donnée fournie"}), 400

    # Champs autorisés pour chaque rôle (tous les champs possibles)
    allowed_fields = {
        "medecin": ["name", "email", "specialite", "adresse", "tel", "gsm", "sexe", "etab", "faculte"],
        "patient": ["name", "email"]
    }
    
    # Filtrer les données pour ne garder que les champs autorisés
    updates = {k: v for k, v in data.items() if k in allowed_fields.get(claims["role"], [])}
    if not updates:
        return jsonify({"message": "Aucun champ valide fourni pour mise à jour"}), 400

    # Mettre à jour dans la bonne collection
    if claims["role"] == "medecin":
        result = medecins.update_one({"_id": ObjectId(user_id)}, {"$set": updates})
        if result.matched_count == 0:
            return jsonify({"message": "Utilisateur non trouvé"}), 404
    elif claims["role"] == "patient":
        result = patients.update_one({"_id": ObjectId(user_id)}, {"$set": updates})
        if result.matched_count == 0:
            return jsonify({"message": "Utilisateur non trouvé"}), 404
    else:
        return jsonify({"message": "Rôle non reconnu"}), 400

    return jsonify({"message": "Profil mis à jour avec succès"}), 200

@app.route('/')
def home():
    return jsonify({"message": "Serveur Flask en marche"}), 200

if __name__ == '__main__':
    init_sqlite_db()
    app.run(debug=True)