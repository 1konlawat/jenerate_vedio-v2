from flask import Flask, render_template, request, redirect, url_for
import sqlite3
# --- เพิ่มไอเทมเทพตรงนี้! ---
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('index.html')

# --- 1. สมัครสมาชิกแบบ Hashing ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # บดรหัสผ่านก่อนลง SQL!
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "อีเมลนี้มีคนใช้แล้วนะ Rick!"
    return render_template('register.html')

# --- 2. เข้าสู่ระบบแบบตรวจสอบ Hash ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        # ตรวจสอบรหัสผ่านที่กรอกมา กับ Hash ใน SQL
        if user and check_password_hash(user[2], password):
            return f"ยินดีต้อนรับกลับมา Rick! (บัญชี: {email})"
        else:
            return "อีเมลหรือรหัสผ่านผิด! ไปตั้งสติแล้วลองใหม่!"
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=False)
