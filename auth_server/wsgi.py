from flask import Flask, redirect, url_for, request, render_template, jsonify

from Crypto.Random import get_random_bytes
import hashlib
import numpy as np

app = Flask(__name__)

users = {}

N = None
g = None
k = None

class User():
    def __init__(self, email, password, d):
        global N, g, k
        self.email = email
        # dont save this!
        self.password = password
        
        self.salt = get_random_bytes(4)
        xH = hashlib.sha256(self.salt+password.encode('utf-8')).hexdigest()
        x = int(xH, 16)
        self.v = pow(g, x, N)
        # add user to dict
        d[email] = self

@app.route('/auth_success/<name>')
def auth_success(name):
    return 'welcome {}'.format(name)

@app.route('/auth_fail')
def auth_fail():
    return 'authentication failed'

@app.route('/',methods=['GET'])
def home():
    global N, g, k, I, P, users
    # assume these can be cast to int
    N = request.args.get('N', type=int)
    g = request.args.get('g', type=int)
    k = request.args.get('k', type=int)
    email = request.args.get('email')
    pwd = request.args.get('password')
    usr = User(email, pwd, users)
    users[email] = usr
    if ((N is None) or (g is None) or (k is None) or (email is None) or (pwd is None)):
        return "failed init", 403
    return {'N':N, 'g':g, 'k':k}, 200




    #return redirect(url_for('login')), 200
    
@app.route('/login',methods=['POST', 'GET'])
def login():
    global N, g, k, users
    if request.method == 'POST':
        email = request.form['email']
        A = request.form['publ_key']
        if email not in users:
            return "user does not exist", 403
        
        usr = users[email]
        # dont save here?
        usr.publ_key = int(A)
        usr.b = np.random.randint(2**16)
        
        exp_term = pow(g, usr.b, N)
        usr.B = (k * usr.v + exp_term) % N
        return {'salt':','.join([str(c) for c in usr.salt]), 'publ_key':usr.B}, 200
    else:
        return render_template('login.html'), 200

    
@app.route('/post_id_pubkey',methods=['POST'])
def post_id_pubkey():
    global N, g, k, users
    if request.method == 'POST':
        email = request.form['email']
        A = request.form['publ_key']
        if email not in users:
            return "user does not exist", 403
        
        usr = users[email]
        # dont save here?
        usr.publ_key = int(A)
        usr.b = np.random.randint(2**16)
        
        exp_term = pow(g, usr.b, N)
        usr.B = (k * usr.v + exp_term) % N
        return {'usr':email, 'publ_key':A}
    
    
@app.route('/authenticate',methods=['POST'])
def authenticate():
    global N, g, k, users
    if request.method == 'POST':
        email = request.form['username']
        hmac = request.form['hmac']

        if email not in users:
            return "user does not exist", 403
        
        usr = users[email]
        
        uH = hashlib.sha256(str(usr.publ_key).encode() + str(usr.B).encode()).hexdigest()
        u = int(uH, 16)

        base = usr.publ_key * pow(usr.v, u, N)
        S = pow(base, usr.b, N)
        K = hashlib.sha256(str(S).encode()).hexdigest()

        own_hmac = hashlib.sha256(K.encode()+usr.salt).hexdigest()
        
        if hmac == own_hmac:
            return "SUCCESS", 200
        else:
            return "FAIL", 200


if __name__ == '__main__':
    app.run(debug=True)
