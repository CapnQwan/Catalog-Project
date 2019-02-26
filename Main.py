from flask import Flask, render_template, url_for

app = Flask(__name__)

@app.route('/')
@app.route('/Corvus')
def homepage():
	return render_template('front_page.html')

@app.route('/login')
def Login():
	return render_template('Login.html')

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)