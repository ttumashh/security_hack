from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
import requests
from fake_useragent import UserAgent
from xml.etree import ElementTree as ET
from bs4 import BeautifulSoup
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:adil@localhost:5432/exploits'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db = SQLAlchemy(app)

class Exploit(db.Model):
    id = db.Column(db.String(100), primary_key=True, unique=True)
    title = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.String(50), nullable=False)

    def __init__(self, id, title, link, description, date):
        self.id = id
        self.title = title
        self.link = link
        self.description = description
        self.date = date
        
    def __repr__(self):
        return self.title
    

@app.route('/api/v1/scan', methods=['POST'])
def scan():
    ua = UserAgent().random
    headers = {'User-Agent': ua}
    data = requests.get('https://sploitus.com/atom', headers=headers).text

    namespace = {'atom': 'http://www.w3.org/2005/Atom'}
    root = ET.fromstring(data)
    entries = root.findall("atom:entry", namespace)
    last_10_entries = entries[-10:]

    for entry in last_10_entries:
        link = entry.find("atom:link", namespace).attrib['href'].split('&')[0]  
        response = requests.get(link, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        code_block = soup.find('pre', class_='centered code')
        
        new_exploit = Exploit(
        id=link[32:],
        title=entry.find("atom:title", namespace).text.strip(), 
        link=link,
        date=entry.find("atom:updated", namespace).text,
        description=code_block.find('code').get_text(),
    )
        
        db.session.add(new_exploit)
    db.session.commit()

    return 'success', 200


@app.route('/api/v1/vulnerabilities', methods=['GET'])
def vulnerabilities():
    last_10_exploits = Exploit.query.order_by(Exploit.date.desc()).limit(10).all()
    result = []
    for exploit in last_10_exploits:
        result.append({
            'id': exploit.id,
            'title': exploit.title,
            'link': exploit.link,
            'description': exploit.description,
            'date': exploit.date
        })

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)