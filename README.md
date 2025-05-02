# Application mobile de gestion médicale

Bienvenue dans le dépôt de l'**Application mobile de gestion médicale**, une application web permettant aux patients de rechercher des médecins, prendre des rendez-vous, gérer des documents, et recevoir des notifications, tandis que les médecins peuvent gérer leurs disponibilités et consulter les documents des patients. Ce projet utilise une architecture client-serveur avec un frontend en **Ionic/Angular** et un backend en **Flask**, avec **MongoDB** pour les données utilisateurs/rendez-vous et **SQLite** pour les documents.

## Fonctionnalités

### Pour les patients
- Inscription et connexion sécurisées
- Recherche de médecins par spécialité, adresse ou nom
- Prise et annulation de rendez-vous
- Envoi de documents (PDF, images) aux médecins
- Gestion du profil et suppression du compte
- Consultation des notifications (ex. rendez-vous confirmés/annulés)

### Pour les médecins
- Gestion des disponibilités (créneaux horaires)
- Consultation et annulation des rendez-vous
- Consultation et téléchargement des documents patients
- Gestion du profil et suppression du compte
- Réception de notifications (ex. nouveaux documents)

## Technologies utilisées
- **Frontend** : Ionic 7, Angular
- **Backend** : Flask, Python 3.8+
- **Bases de données** :
  - MongoDB : Utilisateurs, rendez-vous, disponibilités, notifications
  - SQLite : Stockage des documents
- **Sécurité** : JWT (authentification), Bcrypt (hachage des mots de passe)
- **Autres** : Flask-CORS, Flask-PyMongo, Flask-JWT-Extended

## Prérequis
- **Node.js** : v16 ou supérieur
- **Python** : v3.8 ou supérieur
- **MongoDB** : v4.4 ou supérieur (local)
- **Ionic CLI** : `npm install -g @ionic/cli`
- **Git** : (optionnel, pour cloner le dépôt)

## Installation

1. **Cloner le dépôt** :
   ```bash
   git clone https://github.com/<Toussema>/<gestion_medicale_ionic>.git
   cd <nom-du-depot>
   ```

2. **Installer le frontend** :
   ```bash
   cd frontend
   npm install
   ```

3. **Installer le backend** :
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   pip install flask flask-pymongo flask-bcrypt flask-jwt-extended flask-cors
   ```

4. **Configurer MongoDB** :
   - Assurez-vous que MongoDB est en cours d'exécution :
     ```bash
     mongod
     ```
   - Créez une base de données `medical_app` :
     ```javascript
     use medical_app
     ```

5. **Base SQLite** :
   - La base `documents.db` sera créée automatiquement au premier upload de document.

## Exécution

1. **Lancer le backend** :
   ```bash
   cd backend
   python app.py
   ```
   Le serveur backend sera disponible sur `http://localhost:5000`.

2. **Lancer le frontend** :
   ```bash
   cd frontend
   ionic serve
   ```
   L'application sera accessible sur `http://localhost:8100`.

3. **Tester l'application** :
   - Accédez à `http://localhost:8100`.
   - Inscrivez-vous en tant que patient via `/register`.
   - Connectez-vous et prenez un rendez-vous.

## Structure du projet

```
<nom-du-depot>/
├── backend/
│   ├── app.py               # Serveur Flask (routes, logique backend)
│   ├── documents.db         # Base SQLite pour les documents (créée automatiquement)
│   └── venv/                # Environnement virtuel Python
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── home/
│   │   │   │   ├── home.page.ts   # Page principale (recherche, rendez-vous)
│   │   │   │   └── home.page.html # Interface utilisateur
│   │   │   ├── services/
│   │   │   │   ├── auth.service.ts       # Gestion authentification
│   │   │   │   └── rendez-vous.service.ts # Gestion rendez-vous/disponibilités
│   │   └── assets/          # Ressources statiques
└── guide d'utilisation.pdf
└── README.md                # Ce fichier
```

## Dépannage

- **MongoDB ne se connecte pas** :
  - Vérifiez que `mongod` est en cours d'exécution.
  - Confirmez l'URI dans `app.py` (ex. `mongodb://localhost:27017/medical_app`).
- **Erreur CORS** :
  - Vérifiez la configuration CORS dans `app.py` :
    ```python
    app.config['CORS_HEADERS'] = 'Content-Type'
    cors = CORS(app, resources={r"/*": {"origins": "http://localhost:8100"}})
    ```
- **Créneaux invalides** :
  - Nettoyez la collection `disponibilite` dans MongoDB :
    ```javascript
    db.disponibilite.updateMany(
      {},
      [
        {
          $set: {
            horaires: {
              $arrayToObject: {
                $map: {
                  input: { $objectToArray: "$horaires" },
                  as: "jour",
                  in: {
                    k: "$$jour.k",
                    v: {
                      $filter: {
                        input: "$$jour.v",
                        as: "creneau",
                        cond: {
                          $and: [
                            { $ne: ["$$creneau.debut", null] },
                            { $ne: ["$$creneau.fin", null] },
                            { $regexMatch: { input: "$$creneau.debut", regex: "^\\d{1,2}:\\d{2}$" } },
                            { $regexMatch: { input: "$$creneau.fin", regex: "^\\d{1,2}:\\d{2}$" } },
                            { $eq: ["$$creneau.est_disponible", true] }
                          ]
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]
    );
    ```
- **Erreurs frontend** :
  - Exécutez `npm install` dans `frontend/` pour mettre à jour les dépendances.
  - Vérifiez les logs dans la console du navigateur.

## Contribution
1. Forkez le dépôt.
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/nom-fonctionnalite`).
3. Commitez vos changements (`git commit -m "Ajout de nom-fonctionnalite"`).
4. Poussez votre branche (`git push origin feature/nom-fonctionnalite`).
5. Créez une Pull Request.
