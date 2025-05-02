from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

def add_gouvernorat_ville_fields():
    try:
        # Connexion à MongoDB
        client = MongoClient("mongodb://localhost:27017/")
        
        # Vérification de la connexion
        client.admin.command('ping')
        print("✅ Connexion à MongoDB réussie")

        # Sélection de la base de données et de la collection
        db = client["medical_app"]
        medecins = db["medecin"]

        # Mise à jour de tous les documents pour ajouter les champs gouvernorat et ville
        result = medecins.update_many(
            { "gouvernorat": { "$exists": False } },
            { "$set": { "gouvernorat": "", "ville": "" } }
        )

        # Affichage du résultat
        print(f"Documents mis à jour : {result.modified_count}")
        print("✅ Migration terminée avec succès")

    except ConnectionFailure as e:
        print(f"❌ Erreur de connexion à MongoDB : {e}")
    except Exception as e:
        print(f"❌ Erreur lors de la migration : {e}")
    finally:
        # Fermeture de la connexion
        client.close()
        print("Connexion à MongoDB fermée")

if __name__ == "__main__":
    add_gouvernorat_ville_fields()