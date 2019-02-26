from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
@app.route('/corvus')
def homepage():
	return render_template('header.html')

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)