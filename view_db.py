from app import app, db
from models import User

with app.app_context():
    users = User.query.all()
    print("\nRegistered Users:")
    print("-" * 50)
    for user in users:
        print(f"ID: {user.id}")
        print(f"Username: {user.username}")
        print(f"Public Key: {user.public_key}")
        print(f"Created At: {user.created_at}")
        print("-" * 50) 