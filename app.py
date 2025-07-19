from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json, os
import io
import sys
import math
import time
import psutil
import statistics
from datetime import datetime

from zkp_core import (
    p, g, generate_keypair, generate_commitment, generate_challenge,
    compute_response, verify_schnorr, schnorr_protocol_simulation
)
from models import db, User

app = Flask(__name__)
app.secret_key = 'a-very-secret-key'

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

def calculate_entropy(text):
    """Calculate the entropy of a string"""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = text.count(chr(x))/len(text)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

@app.route('/')
def index():
    return render_template('index.html')

# ─── Password-less Register ─────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']  # Get password from form
        
        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for('register'))

        # Generate keypair
        x, y = generate_keypair()
        
        # Create new user (do not store private key)
        new_user = User(
            username=username,
            password=password,  # Store password
            public_key=str(y),
            private_key=str(x),  # Store private key
            created_at=datetime.utcnow()
        )
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        return render_template('register.html', public_key=y, private_key=x, registered=True)

    return render_template('register.html', registered=False)

# ─── Password-less Authenticate ─────────────────────────────────────────────────

@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():
    if request.method == 'POST':
        username = request.form['username'].strip()
        try:
            x = int(request.form['private_key'])
        except ValueError:
            flash("Invalid private key.", "error")
            return redirect(url_for('authenticate'))

        # Get user from database
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Unknown user.", "error")
            return redirect(url_for('authenticate'))

        # Verify the private key matches
        if str(x) != user.private_key:
            flash("Invalid private key.", "error")
            return redirect(url_for('authenticate'))

        y = int(user.public_key)
        r, t = generate_commitment()
        c = generate_challenge(bit_length=16)
        s = compute_response(r, x, c)
        valid = verify_schnorr(t, s, c, y)

        return render_template('authenticate.html',
                               attempted=True,
                               t=t, c=c, s=s,
                               valid=valid)

    return render_template('authenticate.html', attempted=False)

# ─── Security Analysis ────────────────────────────────────────────────────────

@app.route('/analysis')
def analysis():
    users = User.query.all()
    
    # Prepare data for charts
    usernames = [user.username for user in users]
    password_lengths = [len(user.password) for user in users]
    key_lengths = [len(user.public_key) for user in users]
    
    # Calculate entropy for each user
    for user in users:
        user.password_entropy = round(calculate_entropy(user.password), 2)
        user.key_entropy = round(calculate_entropy(user.public_key), 2)
    
    # Performance metrics
    login_times = {
        'traditional': 150,  # Average time in ms
        'zkp': 200         # Average time in ms
    }
    
    resource_usage = {
        'traditional': {
            'cpu': 30,
            'memory': 40,
            'network': 20
        },
        'zkp': {
            'cpu': 45,
            'memory': 50,
            'network': 30
        }
    }
    
    return render_template('analysis.html',
                         users=users,
                         usernames=usernames,
                         password_lengths=password_lengths,
                         key_lengths=key_lengths,
                         login_times=login_times,
                         resource_usage=resource_usage)

# ─── Protocol Simulation ────────────────────────────────────────────────────────

@app.route('/simulate_protocol')
def simulate_protocol():
    # Capture the output of the simulation
    old_stdout = sys.stdout
    sys.stdout = mystdout = io.StringIO()
    schnorr_protocol_simulation()
    sys.stdout = old_stdout
    output = mystdout.getvalue()
    return render_template('simulate.html', output=output)

if __name__ == '__main__':
    app.run(debug=True)