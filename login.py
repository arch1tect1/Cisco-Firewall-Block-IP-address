import sqlite3
from hashlib import sha256

def check_credentials(username, password):
    con = sqlite3.connect("./databases/users.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("""SELECT * FROM users_table WHERE USERNAME=?""",(username,))
    result = cur.fetchone()
    hashed_password = sha256(password.encode('utf-8')).hexdigest()

    if result:
        if hashed_password == result[1]:
            con.close()
            return True
        else:
            con.close()
            return False
        
def check_current_password(user,curr_pass):
    con = sqlite3.connect("./databases/users.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("""SELECT PASSWORD FROM users_table WHERE USERNAME=?""",(user,))
    result = cur.fetchone()
    con.close()

    print(result)
        
    if result[0] == sha256(curr_pass.encode('utf-8')).hexdigest():
        return True
    else:
        return False

def change_user_password(user, new_pass):
    hashed_password = sha256(new_pass.encode('utf-8')).hexdigest()

    con = sqlite3.connect("./databases/users.sqlite", check_same_thread=False)
    cur = con.cursor()
    cur.execute("""UPDATE users_table SET PASSWORD=? WHERE USERNAME=?""",(hashed_password,user,))
    con.commit()
    con.close()
    
def user_login(username, password):

    if check_credentials(username, password):
        return True
    else:
        return False

if __name__ == '__main__':
    print(user_login("test1","test"))