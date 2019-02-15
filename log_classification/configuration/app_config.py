from flask import Flask
from flask_cors import CORS
from flask_restplus import Api
from flask_sqlalchemy import SQLAlchemy

from configuration.connection import database_uri

app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI=database_uri,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)
api = Api(app, version='1.0', title='Network for chobot project')
ns = api.namespace('')
CORS(app)
db = SQLAlchemy(app)
