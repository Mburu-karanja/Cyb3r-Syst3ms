import sqlite3
from flask import Flask, request, render_template, redirect, session
import pyotp, qrcode, io, base64, bcrypt

app = Flask(__name__)
app.secret_key = 'super-secret'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        secret = pyotp.random_base32()

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, secret) VALUES (?, ?, ?)", 
                      (username, hashed_pw, secret))
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            return "Username already exists."

        # Generate QR code
        totp_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="2FA App")
        qr = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format='PNG')
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()

        return render_template('qrcode.html', qr_data=qr_b64)
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        result = c.fetchone()
        conn.close()

        if result and bcrypt.checkpw(password, result[0]):
            session['username'] = username
            return redirect('/verify')
        return "Invalid credentials."
    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session:
        return redirect('/login')

    if request.method == 'POST':
        otp = request.form['otp']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT secret FROM users WHERE username=?", (session['username'],))
        result = c.fetchone()
        conn.close()

        if result:
            totp = pyotp.TOTP(result[0])
            if totp.verify(otp):
                return """
            <pre>
                                                                             ,--, 
          ____                                        ,-.      ,--.'| 
        ,'  , `.  ,---,                           ,--/ /|   ,--,  | : 
     ,-+-,.' _ |,---.'|            ,--,  __  ,-.,--. :/ |,---.'|  : ' 
  ,-+-. ;   , |||   | :          ,'_ /|,' ,'/ /|:  : ' / ;   : |  | ; 
 ,--.'|'   |  ||:   : :     .--. |  | :'  | |' ||  '  /  |   | : _' | 
|   |  ,', |  |,:     |,-.,'_ /| :  . ||  |   ,''  |  :  :   : |.'  | 
|   | /  | |--' |   : '  ||  ' | |  . .'  :  /  |  |   \ |   ' '  ; : 
|   : |  | ,    |   |  / :|  | ' |  | ||  | '   '  : |. \\   \  .'. | 
|   : |  |/     '   : |: |:  | : ;  ; |;  : |   |  | ' \ \`---`:  | ' 
|   | |`-'      |   | '/ :'  :  `--'   \  , ;   '  : |--'      '  ; | 
|   ;/          |   :    |:  ,      .-./---'    ;  |,'         |  : ; 
'---'           /    \  /  `--`----'            '--'           '  ,/  
   ,--,         `-'----'                                       '--'   
,---.'|  .--,-``-.            ,--,                    ,--.            
|   | : /   /     '.        ,--.'|,-.----.          ,--.'|            
:   : |/ ../        ;    ,--,  | :\    /  \     ,--,:  : |            
|   ' :\ ``\  .`-    ',---.'|  : ';   :    \ ,`--.'`|  ' :            
;   ; ' \___\/   \   :;   : |  | ;|   | .\ : |   :  :  | |            
'   | |__    \   :   ||   | : _' |.   : |: | :   |   \ | :            
|   | :.'|   /  /   / :   : |.'  ||   |  \ : |   : '  '; |            
'   :    ;   \  \   \ |   ' '  ; :|   : .  / '   ' ;.    ;            
|   |  ./___ /   :   |\   \  .'. |;   | |  \ |   | | \   |            
;   : ; /   /\   /   : `---`:  | '|   | ;\  \'   : |  ; .'            
|   ,/ / ,,/  ',-    .      '  ; |:   ' | \.'|   | '`--'              
'---'  \ ''\        ;       |  : ;:   : :-'  '   : |                  
        \   \     .'        '  ,/ |   |.'    ;   |.'                  
         `--`-,,-'          '--'  `---'      '---'                    
                                                                      
            ─────────────────────────
            (•̀ᴗ•́)و ̑̑ You're In! Welcome to the secure zone! 
            </pre>
        """
            else:
                return """<pre>
                                                             ,---,  
    ,----..                                   ,`--.' |  
   /   /   \                                  |   :  :  
  /   .     :           ,-.----.              '   '  ;  
 .   /   ;.  \   ,---.  \    /  \             |   |  |  
.   ;   /  ` ;  '   ,'\ |   :    |  .--.--.   '   :  ;  
;   |  ; \ ; | /   /   ||   | .\ : /  /    '  |   |  '  
|   :  | ; | '.   ; ,. :.   : |: ||  :  /`./  '   :  |  
.   |  ' ' ' :'   | |: :|   |  \ :|  :  ;_    ;   |  ;  
'   ;  \; /  |'   | .; :|   : .  | \  \    `. `---'. |  
 \   \  ',  / |   :    |:     |`-'  `----.   \ `--..`;  
  ;   :    /   \   \  / :   : :    /  /`--'  /.--,_     
   \   \ .'     `----'  |   | :   '--'.     / |    |`.  
    `---`               `---'.|     `--'---'  `-- -`, ; 
            ─────────────────────────
                ❌ Invalid OTP.
            </pre>"""
    return render_template('verify.html')


def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    secret TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

init_db()
if __name__ == '__main__':
    app.run(debug=True)
