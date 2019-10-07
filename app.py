import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow


# init app
app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# database
DB_URI = "mysql+mysqlconnector://appyens:Gpa$$i0n@localhost:3306/threatdb"
DB_URI2 = 'sqlite:///' + os.path.join(BASE_DIR, 'db.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# init database
db = SQLAlchemy(app)
# init ma
ma = Marshmallow(app)


class BlockedIPs(db.Model):
    __tablename__ = 'blocked_ips'
    id = db.Column('id', db.INTEGER, primary_key=True)
    ip_address = db.Column('ip_address', db.String(50), nullable=False)
    reliability = db.Column('reliability', db.INTEGER, nullable=True)
    priority = db.Column('priority', db.INTEGER, nullable=True)
    activity = db.Column('activity', db.String(128), nullable=True)
    sub_category = db.Column('sub_category', db.String(128), nullable=True)
    country = db.Column('country', db.String(128), nullable=True)
    city = db.Column('city', db.String(128), nullable=True)
    latitude = db.Column('latitude', db.FLOAT, nullable=True)
    longitude = db.Column('longitude', db.FLOAT, nullable=True)
    source = db.Column('source', db.String(128), nullable=True)
    target = db.Column('target', db.String(128), nullable=True)
    dest_port = db.Column('dest_port', db.INTEGER, nullable=True)
    last_online = db.Column('last_online', db.String(128), nullable=True)
    first_seen = db.Column('first_seen', db.String(128), nullable=True)
    used_by = db.Column('used_by', db.String(128), nullable=True)
    reference_link = db.Column('reference_link', db.String(128), nullable=True)
    created_at = db.Column('created_at', db.TIMESTAMP, nullable=False,  default=datetime.utcnow)
    updated_at = db.Column('updated_at', db.TIMESTAMP, nullable=False, default=datetime.utcnow)
    revision = db.Column('revision', db.INTEGER, nullable=False)

    # constructor
    def __init__(self, ip_address, revision):
        self.ip_address = ip_address
        self.revision = revision

    def __str__(self):
        return self.ip_address


class MalwareURLs(db.Model):
    __tablename__ = 'malware_urls'
    id = db.Column('id', db.INTEGER, primary_key=True)
    url = db.Column('url', db.String(256), nullable=False)
    domain = db.Column('domain', db.String(256), nullable=True)
    filename = db.Column('filename', db.String(256), nullable=True)
    priority = db.Column('priority', db.String(256), nullable=True)
    file_type = db.Column('file_type', db.String(256), nullable=True)
    country = db.Column('country', db.String(256), nullable=True)
    url_status = db.Column('url_status', db.String(256), nullable=True)
    date_added = db.Column('date_added', db.String(256), nullable=True)
    threat_type = db.Column('threat_type', db.String(256), nullable=True)
    threat_tag = db.Column('threat_tag', db.String(256), nullable=True)
    created_at = db.Column('created_at', db.TIMESTAMP, nullable=False, default=datetime.utcnow)
    updated_at = db.Column('updated_at', db.TIMESTAMP, nullable=False, default=datetime.utcnow)


# blocked_ips schema
class BlockedIPsSchema(ma.Schema):
    class Meta:
        fields = ('id', 'ip_address', 'revision')


class MalwareURLsSchema(ma.Schema):
    class Meta:
        fields = (
            'id', 'url', 'domain', 'filename', 'priority',
            'file_type', 'country', 'url_status', 'date_added',
            'threat_type', 'threat_tag', 'created_at', 'updated_at',
        )

# init schema
blocked_ip_schema = BlockedIPsSchema()
blocked_ips_schema = BlockedIPsSchema(many=True)
malware_url_schema = MalwareURLsSchema()
malware_urls_schema = MalwareURLsSchema(many=True)


@app.route('/create', methods=['POST'])
def add_ip():
    ip = request.json['ip_address']
    rev = request.json['revision']
    new_ip = BlockedIPs(ip, rev)
    db.session.add(new_ip)
    db.session.commit()
    return blocked_ip_schema.jsonify(new_ip)


@app.route('/get', methods=['GET'])
def get_list():
    all_ip = BlockedIPs.query.all()
    result = blocked_ips_schema.dump(all_ip)
    return jsonify(result)


@app.route('/ip/search/<ip>', methods=['GET'])
def search_ip(ip):
    ip = BlockedIPs.query.filter_by(ip_address=ip).first()
    result = blocked_ip_schema.jsonify(ip)
    return result


@app.route('/update/<id>', methods=['PUT'])
def update_ip(id):
    item = BlockedIPs.query.get(id)
    ip = request.json['ip_address']
    rev = request.json['revision']
    item.ip_address = ip
    item.revision = rev
    db.session.commit()
    return blocked_ip_schema.jsonify(item)


@app.route('/delete/<id>', methods=['DELETE'])
def delete_ip(id):
    item = BlockedIPs.query.get(id)
    db.session.delete(item)
    db.session.commit()
    return blocked_ip_schema.jsonify(item)


@app.route('/url/list', methods=['GET'])
def url_list():
    q = request.args['threat_type']
    if q == 'Malware':
        urls = MalwareURLs.query.filter_by(threat_type=q)
        result = malware_urls_schema.dump(urls)
        return result
    elif q == 'Phishing':
        urls = MalwareURLs.query.filter_by(threat_type=q)
        result = malware_urls_schema.dump(urls)
        return result
    elif q == 'Ransomware':
        urls = MalwareURLs.query.filter_by(threat_type=q)
        result = malware_urls_schema.dump(urls)
        return result
    else:
        return {'error': "Please provide valid query"}


# 2 search url
@app.route('/url/search/<url>', methods=['GET'])
def search_ip(url):
    ip = MalwareURLs.query.filter_by(MalwareURLs.url.ilike(url)).first()
    result = blocked_ip_schema.jsonify(ip)
    return result

@app.route('/')
def hello_world():
    return 'Hello World!'


# runserver
if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=True)
