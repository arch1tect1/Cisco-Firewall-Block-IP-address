import sqlite3
from flask import Flask, render_template, make_response, redirect, url_for, request
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from login import user_login, check_current_password, change_user_password
from securex import get_token, block_ip_address, unblock_ip_address, associate_ip_and_jobid, jobid_of_ip, delete_job, unblock_permanently_blocked
from abuse_ip import blocktime_basedon_abusescore, check_abuse_score

app = Flask(__name__)
CORS(app)

get_token()

scheduler = BackgroundScheduler()
scheduler.add_jobstore('sqlalchemy', url='sqlite:///databases/job_store.sqlite')
scheduler.start()
scheduler.add_job(get_token, 'interval', minutes=10)


@app.route('/unblock-ip', methods=['POST'])
def unblock_ip():
    ip_address = request.json.get('ipAddress')
    user = request.json.get('user')

    if user == None:
        response = make_response("Login Required")
        response.status_code = 302
        return response

    con = sqlite3.connect("./databases/blocked_ips.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("""SELECT IP FROM ips WHERE IP=?""",(ip_address,))
    result = cur.fetchone()
    con.close()
    if not result:
        result = unblock_permanently_blocked(ip_address,user)
        if result.status_code == 200:
            response = make_response ("IP unblocked successfully",200)
            return response
        else:
            response = make_response("Something went wrong", 500)
            return response

    unblock_result = unblock_ip_address(ip_address, user)

    if unblock_result.status_code == 200:
        response = make_response ("IP unblocked successfully",200)
        return response
    else:
        response = make_response("Something went wrong", 500)
        return response

@app.route('/block-ip', methods=['POST'])
def block_ip():
    ip_address = request.json.get('ipAddress')
    time_amount = request.json.get('timeRange')
    user = request.json.get('user')
    now = datetime.now()
    time_result = None

    if user == None:
        response = make_response("Login Required")
        response.status_code = 302
        return response

    if time_amount != 'auto':
        time_result = now + timedelta(hours=int(time_amount))
    elif time_amount == 'auto':
        time_result = now + timedelta(hours=blocktime_basedon_abusescore(check_abuse_score(ip_address)))
    
    con = sqlite3.connect("./databases/blocked_ips.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("""SELECT IP FROM ips WHERE IP=?""",(ip_address,))
    result = cur.fetchone()
    con.close()

    if result:
        print("IP already added to blacklist")
        response = make_response("IP already blocked")
        response.status_code = 409
        return response
    
    if time_amount == 'auto':
        abuse_score = check_abuse_score(ip_address)
        block_time = blocktime_basedon_abusescore(abuse_score)
        block_result = block_ip_address(ip_address,block_time,user,now,time_result)
        if block_result.status_code == 200:
            job = scheduler.add_job(unblock_ip_address, 'date', run_date=time_result, args=[ip_address], misfire_grace_time=432000)
            job_id = job.id
            associate_ip_and_jobid(job_id, ip_address)
            response = make_response("Abuse percentage of IP address is {score} and blocked for {time} hours".format(score=abuse_score, time=block_time),200)
            return response
        else:
            response = make_response("Something went wrong",500)
            return response
    else:
        block_result = block_ip_address(ip_address,int(time_amount),user,now,time_result)
        if block_result.status_code == 200:
            job = scheduler.add_job(unblock_ip_address, 'date', run_date=time_result, args=[ip_address], misfire_grace_time=432000)
            job_id = job.id
            associate_ip_and_jobid(job_id, ip_address)
            response = make_response("IP blocked successfully for {time} hours".format(time=time_amount),200)
            return response
        else:
            response = make_response("Something went wrong",500)
            return response


@app.route("/", methods=['GET'])
def home():
    cookie = request.cookies.get("user")
    
    con = sqlite3.connect("./databases/users.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("""SELECT * FROM users_table WHERE USERNAME=?""",(cookie,))
    result = cur.fetchone()

    if result:
        return render_template('index.html')
    
    return redirect(url_for('login'))
    
    
@app.route("/blocked-ips",methods=['GET'])
def blocked_ips():
    con = sqlite3.connect("./databases/blocked_ips.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("SELECT * FROM ips")
    data = cur.fetchall()
    con.close()
    return render_template('blocked_ips.html', data=data)


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.json.get('username')
        password = request.json.get('password')
        login_result = user_login(username,password)
        print(login_result)
        if not login_result:
            response = make_response("Authentication failed")
            response.status_code = 401
            return response
        else:
            response = make_response("Success")
            response.status_code = 200
            return response
        
    response = make_response(render_template("login.html"))
    return response

@app.route('/change-password',methods=['GET','POST'])
def change_password():
    if request.method == 'POST':
        cur_pass = request.json.get('cur_pass')
        new_pass = request.json.get('new_pass')
        user = request.json.get('user')

        if user == "None":
            return redirect(url_for('login'))

        if check_current_password(user, cur_pass):
            print('checking')
            change_user_password(user, new_pass)
            response = make_response("Success")
            response.status_code = 200
        else:
            response = make_response("Update Failed")
            response.status_code = 400
            return response

    response = make_response(render_template("change_password.html"))
    return response

if __name__ == '__main__':
    app.run(debug=True)
