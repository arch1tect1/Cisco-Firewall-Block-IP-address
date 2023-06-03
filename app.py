from flask import Flask, render_template, request, redirect, session
import sqlite3
import hashlib
from datetime import datetime


app = Flask(__name__)
app.secret_key = 'your_secret_key'

access_token = "" # from Cisco SecureX


# SQLite db creation
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Table creation if not exists
c.execute('''CREATE TABLE IF NOT EXISTS users 
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              password TEXT NOT NULL)''')
conn.commit()
conn.close()


# new user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return "Password are not matched!"
        
        # hashing with SHA256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if result:
            return "User exists!"
        
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  (username, hashed_password))
        conn.commit()
        conn.close()
        
        return redirect('/login')
    
    return render_template('register.html')


# profile page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute("SELECT * FROM users WHERE username=? AND password=?",
                  (username, hashed_password))
        result = c.fetchone()
        
        conn.close()
        
        if result:
            session['username'] = username
            return redirect('/profile')
        else:
            return "Incorrect username or password!"
    
    return render_template('login.html')


# logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')


# change password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        username = session['username']
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            return "Password are not matched!"
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if result:
            stored_password = result[2]
            
            if hashlib.sha256(old_password.encode()).hexdigest() == stored_password:
                # password updating
                hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                c.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
                conn.commit()
                conn.close()
                
                return "Password changed successfully!"
        
        conn.close()
        return "Wrong password!"
    
    return render_template('change_password.html')


# routes protection using decorators
@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template('profile.html')
    else:
        return redirect('/login')


#-----------------------------------Cisco SecureX part----------------------------------------------#

def delete_job(jobid):
    con = sqlite3.connect("./databases/job_store.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("DELETE FROM apscheduler_jobs WHERE id = ?",(jobid,))
    con.commit()
    con.close()


def associate_ip_and_jobid(jobid, ip):
    con = sqlite3.connect("./databases/jobs.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("INSERT INTO job_data VALUES (? , ?)",(jobid, ip))
    con.commit()
    con.close()


def jobid_of_ip(ip):
    con = sqlite3.connect("./databases/jobs.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("SELECT job_id from job_data WHERE ip_address = ?", (ip,))
    row = cur.fetchone()
    job_id = row[0]
    cur.execute("DELETE FROM job_data WHERE ip_address = ?",(ip,))
    con.commit()
    con.close()

    return job_id 


def block_ip_address(ip_address, duration, user, block_time, unblock_time):

    url = 'https://visibility.apjc.amp.cisco.com/iroh/iroh-response/respond/trigger/your_action_url_with_action_id='+ip_address

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json', 'Authorization': 'Bearer ' + access_token}

    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        with open("./logs.txt", "a") as f:
                f.write("[" + str(datetime.now()) + "] " + "{ip_address} sent to block by {user} and will be unblocked on {time_result} \n".format(ip_address=ip_address, user=user, time_result=str(unblock_time)))
        con = sqlite3.connect("./databases/blocked_ips.sqlite", check_same_thread=False)
        cur = con.cursor()
        cur.execute("INSERT INTO ips VALUES (?, ?, ?, ?, ?)", (ip_address, user, block_time, duration, unblock_time))
        con.commit()
        con.close()

    return response


def unblock_ip_address(ip_address, user="Robot"):

    url = 'https://visibility.apjc.amp.cisco.com/iroh/iroh-response/respond/trigger/your_action_url_with_action_id='+ip_address

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json', 'Authorization': 'Bearer ' + access_token}

    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        if user != "Robot":
            jobid = jobid_of_ip(ip_address)
            delete_job(jobid)

        with open("./logs.txt", "a") as f:
            f.write("[" + str(datetime.now()) + "] " + "{ip_address} unblocked by {user} \n".format(ip_address=ip_address, user=user))

        con = sqlite3.connect("./databases/blocked_ips.sqlite", check_same_thread=False)
        cur = con.cursor()
        cur.execute("DELETE FROM ips WHERE IP = ?", (ip_address,))
        con.commit()
        con.close()
    
    return response


def unblock_permanently_blocked(ip_address,user):
    url = 'https://visibility.apjc.amp.cisco.com/iroh/iroh-response/respond/trigger/your_action_url_with_action_id'+ip_address

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json', 'Authorization': 'Bearer ' + access_token}

    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        with open("./logs.txt", "a") as f:
            f.write("[" + str(datetime.now()) + "] " + "{ip_address} unblocked by {user} \n".format(ip_address=ip_address, user=user))

    return response


def get_token():

    client_id = ''
    client_password = ''
    url = 'https://visibility.apjc.amp.cisco.com/iroh/oauth2/token'

    global access_token

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}

    payload = {'grant_type':'client_credentials'}

    response = requests.post(url, headers=headers, auth=(client_id, client_password), data=payload)

    json_data = response.json()

    access_token = json_data['access_token']


if __name__ == '__main__':
    app.run(debug=True)
