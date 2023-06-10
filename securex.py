import requests
import sqlite3
from datetime import datetime

access_token = ""

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

    url = 'https://visibility.apjc.amp.cisco.com/iroh/iroh-response/respond/trigger/87e7c012-3456-434e-b982-6849856efceb/0252ZOKRSO3N56BkKnHoYAlSNIKlIcXe6XA?action_id=0252ZOKRSO3N56BkKnHoYAlSNIKlIcXe6XA&observable_type=ip&observable_value='+ip_address

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

    url = 'https://visibility.apjc.amp.cisco.com/iroh/iroh-response/respond/trigger/87e7c012-3456-434e-b982-6849856efceb/024W3ZJQVKRQ80BHwW0FznlUF8mSy4ADknV?action_id=024W3ZJQVKRQ80BHwW0FznlUF8mSy4ADknV&observable_type=ip&observable_value='+ip_address

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
    url = 'https://visibility.apjc.amp.cisco.com/iroh/iroh-response/respond/trigger/87e7c012-3456-434e-b982-6849856efceb/024W3ZJQVKRQ80BHwW0FznlUF8mSy4ADknV?action_id=024W3ZJQVKRQ80BHwW0FznlUF8mSy4ADknV&observable_type=ip&observable_value='+ip_address

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json', 'Authorization': 'Bearer ' + access_token}

    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        with open("./logs.txt", "a") as f:
            f.write("[" + str(datetime.now()) + "] " + "{ip_address} unblocked by {user} \n".format(ip_address=ip_address, user=user))

    return response


def get_token():

    client_id = 'client-279521e6-495c-46bd-8966-aa5189727977'
    client_password = 'QlGIhnVwPMOR-MuAnX1AkSVTrMU0n2lEPr5JHLVlOno45RcAhVXY4w'
    url = 'https://visibility.apjc.amp.cisco.com/iroh/oauth2/token'

    global access_token

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}

    payload = {'grant_type':'client_credentials'}

    response = requests.post(url, headers=headers, auth=(client_id, client_password), data=payload)

    json_data = response.json()

    access_token = json_data['access_token']
