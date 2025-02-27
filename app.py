from flask import Flask, render_template, redirect, request, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import datetime
import base64

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- DATABASE MODELS --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'user' or 'admin'

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    photo_path = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'punch-in' or 'punch-out'
    latitude = db.Column(db.String(20), nullable=True)
    longitude = db.Column(db.String(20), nullable=True)

# -------------------- ROUTES --------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists!"

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        return "Invalid credentials!"

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        attendance_records = Attendance.query.all()
    else:
        attendance_records = Attendance.query.filter_by(user_id=current_user.id).all()
    
    return render_template('dashboard.html', records=attendance_records, user=current_user)

@app.route('/punch/<punch_type>', methods=['GET'])
@login_required
def punch(punch_type):
    if punch_type not in ['punch-in', 'punch-out']:
        return "Invalid request"

    return render_template('capture.html', punch_type=punch_type)

@app.route('/save_punch', methods=['POST'])
@login_required
def save_punch():
    photo_data = request.form['photo']
    latitude = request.form['latitude']
    longitude = request.form['longitude']
    punch_type = request.form['punch_type']

    folder = 'static/selfies'
    os.makedirs(folder, exist_ok=True)
    photo_path = f"{folder}/{current_user.username}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"

    with open(photo_path, "wb") as file:
        file.write(base64.b64decode(photo_data.split(',')[1]))

    new_attendance = Attendance(user_id=current_user.id, photo_path=photo_path, type=punch_type, latitude=latitude, longitude=longitude)
    db.session.add(new_attendance)
    db.session.commit()

    flash("Punch recorded successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.getenv("PORT", 10000))  # Render provides a PORT environment variable
    app.run(host="0.0.0.0", port=port)
