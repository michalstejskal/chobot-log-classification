import configparser
import os

from flask import Flask, url_for, Blueprint
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_restplus import Api, apidoc
from flask_sqlalchemy import SQLAlchemy

environment = os.environ['ENVIRONMENT']
docs_location = os.environ['API_URI']
if environment == 'DEVEL':
    config_file = open('../resources/environment_configuration.cfg', 'r')
else:
    config_file = open('resources/environment_configuration.cfg', 'r')

configuration = configparser.ConfigParser()
configuration.read_file(config_file)
api_port = configuration.get(environment, 'application_port')
debug_server = configuration.get(environment, 'application_debug')
model_data_path = configuration.get(environment, 'model_data_path')

database_uri = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser=configuration.get(environment, 'db_user'), dbpass=configuration.get(environment, 'db_password'),
    dbhost=configuration.get(environment, 'database_connection'), dbname=configuration.get(environment, 'db_name'))

app = Flask(__name__)
app.config.update(SQLALCHEMY_DATABASE_URI=database_uri, SQLALCHEMY_TRACK_MODIFICATIONS=False, )
api = Api(app, version='1.0', title='Network for chobot project', url_prefix=docs_location)

swagger_apidoc_static = apidoc.Apidoc('restplus_custom_doc', __name__, template_folder='templates',
                                      static_folder=os.path.dirname(apidoc.__file__) + '/static',
                                      static_url_path='/swaggerui')


@swagger_apidoc_static.add_app_template_global
def swagger_static(filename):
    return url_for('restplus_custom_doc.static', filename='{0}'.format(filename))


app.register_blueprint(swagger_apidoc_static, url_prefix=docs_location)

ns = api.namespace('')
CORS(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
