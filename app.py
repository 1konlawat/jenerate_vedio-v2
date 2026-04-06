from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- ตั้งค่า Path ของฐานข้อมูลให้ชัดเจน ---
# วิธีนี้จะทำให้ Render หาไฟล์ database.db เจอแน่นอน ไม่ว่าจะรันจากโฟลเดอร์ไหน
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
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

# รันฟังก์ชันสร้าง DB ทันทีที่แอปเริ่มทำงาน
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
        
        # ใช้ pbkdf2:sha256 (มาตรฐานความปลอดภัย)
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            conn = sqlite3.connect(DB_PATH)
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
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            return f"ยินดีต้อนรับกลับมา Rick! (บัญชี: {email})"
        else:
            return "อีเมลหรือรหัสผ่านผิด! ไปตั้งสติแล้วลองใหม่!"
    return render_template('login.html')

if __name__ == '__main__':
    # ส่วนสำคัญสำหรับการออนไลน์: 
    # Render จะส่งพอร์ตมาให้ผ่าน Environment Variable ชื่อ PORT
    port = int(os.environ.get("PORT", 10000))
    # ต้องใช้ host='0.0.0.0' เพื่อเปิดรับการเชื่อมต่อจากภายนอก
    app.run(host='0.0.0.0', port=port, debug=False)
