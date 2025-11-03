from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello World!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Add your authentication logic here
        if username == 'admin' and password == 'secret':
            return redirect(url_for('index')) 
        else:
            error = 'Invalid credentials, please try again.'
    
    return render_template('login.html', error=error)

