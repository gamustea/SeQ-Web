from src.logic.secrets import Encoder

password = "root"
salt = Encoder.generate_salt()
hashed_password = Encoder.hash_password_with_salt(password, salt)

print(f"Password: {password}")
print(f"Salt: {salt}")
print(f"Hashed Password: {hashed_password}")

print(Encoder.verify_password(hashed_password, password, salt))