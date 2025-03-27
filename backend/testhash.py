from app import bcrypt
stored_hash = "$2b$12$PmSqUuK6TIZnGnLodOqHoO.EG5OSSVC6tCPnRGVn7VE5umFWnNSem"  # Copiez le hash de votre DB
print(bcrypt.check_password_hash(stored_hash, "motdepasse"))  # Doit retourner True