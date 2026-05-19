from flask import Flask, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

@app.route('/ash_agent')
def ash_agent():
    return send_from_directory('.', 'ash_advisor.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
