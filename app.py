from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'clave_secreta'

def get_db():
    conn = sqlite3.connect('tareas.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        description TEXT,
                        completed BOOLEAN DEFAULT 0,
                        user_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(user_id) REFERENCES users(id))''')

@app.route('/')
def index():
    db = get_db()
    tasks = db.execute('SELECT * FROM tasks').fetchall()
    return render_template('index.html', tasks=tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        try:
            db = get_db()
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password))
            db.commit()
            flash('Usuario registrado exitosamente.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nombre de usuario ya existe.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            flash('Usuario o contraseña incorrectos')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        db.execute('INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)',
                   (title, description, session['user_id']))
        db.commit()
        return redirect('/dashboard')

    tasks = db.execute('SELECT * FROM tasks WHERE user_id = ?', (session['user_id'],)).fetchall()
    return render_template('dashboard.html', tasks=tasks)

@app.route('/completar/<int:id>')
def completar(id):
    db = get_db()
    db.execute('UPDATE tasks SET completed = 1 WHERE id = ?', (id,))
    db.commit()
    return redirect('/dashboard')

@app.route('/eliminar/<int:id>')
def eliminar(id):
    db = get_db()
    db.execute('DELETE FROM tasks WHERE id = ?', (id,))
    db.commit()
    return redirect('/dashboard')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
