import base64
import binascii
import json
import os
from functools import wraps

import requests
from configuration.app_config import app, db, ns, api
from configuration.connection import connection_port
from flask import abort
from flask import jsonify, request
from flask_restful_swagger import swagger
from flask_restplus import Resource
from models.models import Network, NetworkParameter
from data_preparator import prepare_data, prepare_log_row
from network_model import load_model, predict, train_model
from sqlalchemy.dialects.postgresql import psycopg2

import psycopg2
import psycopg2.extensions
psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)


def require_appkey(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        print('check authorization')
        api_key_result, network = check_api_key(request)
        if api_key_result:
            if check_secret(request, network):
                return view_function(*args, **kwargs)

        print('request abbort -- 401')
        abort(401)

    return decorated_function


def check_api_key(request_input):
    if request_input.headers.get('Authorization'):
        print('check api key')
        api_key_dict = convert_to_dict(request_input.headers.get('Authorization'))
        id = api_key_dict['network_id']
        api_key_secret = api_key_dict['api_key']
        request_input.headers.get('netw-sec: ' + api_key_secret)

        try:
            network = db.session.query(Network).get(id)
        except:
            db.session.commit()
            db.session.close()
            network = db.session.query(Network).get(id)

        if network is not None and network.network_id == id and network.api_key_secret == api_key_secret:
            print('api key check successful')
            print(network)
            return True, network

    print('api key check unsuccessful')
    return False, None


def check_secret(request_input, network):
    if request_input.headers.get('Secret'):
        print('check user secret')
        secret_dict = convert_to_dict(request_input.headers.get('Secret'))
        if network.user.secret == secret_dict['secret']:
            print('check user secret successful')
            db.session.commit()
            db.session.close()
            return True
    print('check user secret unsuccessful')
    db.session.commit()
    db.session.close()
    return False


def convert_to_dict(request_header):
    try:
        input_json = base64.b64decode(str(request_header))
        return json.loads(input_json.decode("utf-8"))
    except binascii.Error:
        print('unable to decode input')
        abort(400)


@ns.route('/healtz')
class HealthController(Resource):
    @swagger.operation()
    def get(self):
        return jsonify("true")


@ns.route('/network/predict')
class NetworkController(Resource):
    '''Predict from user image'''

    post_parser = api.parser()
    post_parser.add_argument('Authorization', type=str, location='headers', required=True)
    post_parser.add_argument('Secret', type=str, location='headers', required=True)

    @api.expect(post_parser, validate=True)
    @require_appkey
    @swagger.operation()
    def post(self):
        data = {"success": False}
        # ensure an image was properly uploaded to our endpoint
        if request.method == "POST":
            if request.data is not None:
                messageDict = request.json
                if messageDict is not None and 'message' in messageDict:
                    log = base64.b64decode(str(messageDict['message']))
                    x = prepare_log_row(log, pattern)
                    if x is not None:
                        classification = predict(x)
                        data["classification"] = classification
                        data["success"] = True

                        network = self.get_network(request.headers.get('Authorization'))
                        data = self.call_modules(network, classification, data)
                else:
                    abort(400)

        db.session.commit()
        db.session.close()
        return jsonify(data)

    def get_network(self, auth_header):
        auth_header = convert_to_dict(auth_header)

        network = db.session.query(Network).get(auth_header['network_id'])
        return network

    def call_modules(self, network, main_label, data):
        for module in network.modules:
            if module.response_class == main_label and module.status == 4:
                headers = {
                    "Authorization": module.api_key,
                    "Secret": module.network.user.secret
                }

                response = requests.get('http://' + module.connection_uri_internal, data=data, headers=headers)
                data['module_response'] = json.loads(response.content.decode("utf-8"))
        return data


def check_if_trained(network):
    trained = False
    train_path = ""
    global pattern
    pattern = None
    for parameter in network.parameters:
        if parameter.abbreviation == "IS_TRAINED":
            trained = True
        if parameter.abbreviation == "TRAIN_DATA_PATH":
            train_path = parameter.value
        if parameter.abbreviation == "DATA_PATTERN":
            pattern = parameter.value

    X = prepare_data(train_path, pattern)
    if trained is False:
        train_model(X)

        p = NetworkParameter()
        p.network_id = network.network_id
        p.name = 'IS_TRAINED'
        p.abbreviation = 'IS_TRAINED'
        p.value = True
        db.session.add(p)
        db.session.commit()
        db.session.close()
        pass
    return X


def get_network():
    network_id = os.environ['NETWORK_ID']
    network = db.session.query(Network).get(network_id)
    train_path = check_if_trained(network)
    return train_path


if __name__ == "__main__":
    print("done")
    X = get_network()
    load_model(X)
    db.session.commit()
    db.session.close()
    app.run(debug=True, host="0.0.0.0", port=connection_port)

# one_row = '2016-06-04	12:00:09	200	94.199.43.237:25689	"-"	GET	"/wwwstats/f"	"?p=105:1:0:::::"	10.245.8.60:443	"www.czechpoint.cz"	HTTP/1.1	592	28765	45877	"-"	"curl/7.19.7 (x86_64-suse-linux-gnu) libcurl/7.19.7 OpenSSL/0.9.8j zlib/1.2.7 libidn/1.10"	"-"	TLSv1	DHE-RSA-AES256-SHA	"-$-"	+	7961	"proxy:http://10.245.10.45/pls/apex/f?p=105:1:0:::::"'
# curl -X POST "localhost:5001/network/predict"  -H "accept: application/json" -H "Authorization: eyJuZXR3b3JrX2lkIjoxMDcsImFwaV9rZXkiOiJTbFJYYW1WU1dWQnhVMDlLVkVsT1RscG1XR0pvVFdsdVltTlJPVzlVYTJzPSJ9" -H "Secret: eyJzZWNyZXQiOiJkR0ZxYm1WZmFHVnpiRzg9In0=" --data '{"message":"2016-06-04	12:00:09	200	94.199.43.237:25689	"-"	GET	"/wwwstats/f"	"?p=105:1:0:::::"	10.245.8.60:443	"www.czechpoint.cz"	HTTP/1.1	592	28765	45877	"-"	"curl/7.19.7 (x86_64-suse-linux-gnu) libcurl/7.19.7 OpenSSL/0.9.8j zlib/1.2.7 libidn/1.10"	"-"	TLSv1	DHE-RSA-AES256-SHA	"-$-"	+	7961	"proxy:http://10.245.10.45/pls/apex/f?p=105:1:0:::::""}' -H "Content-Type: application/json"
# curl -X POST "localhost:5001/network/predict"  -H "accept: application/json" -H "Authorization: eyJuZXR3b3JrX2lkIjoxMDcsImFwaV9rZXkiOiJTbFJYYW1WU1dWQnhVMDlLVkVsT1RscG1XR0pvVFdsdVltTlJPVzlVYTJzPSJ9" -H "Secret: eyJzZWNyZXQiOiJkR0ZxYm1WZmFHVnpiRzg9In0=" --data '{"message":"MjAxNi0wNi0wNAkxMjowMDowOQkyMDAJOTQuMTk5LjQzLjIzNzoyNTY4OQkiLSIJR0VUCSIvd3d3c3RhdHMvZiIJIj9wPTEwNToxOjA6Ojo6OiIJMTAuMjQ1LjguNjA6NDQzCSJ3d3cuY3plY2hwb2ludC5jeiIJSFRUUC8xLjEJNTkyCTI4NzY1CTQ1ODc3CSItIgkiY3VybC83LjE5LjcgKHg4Nl82NC1zdXNlLWxpbnV4LWdudSkgbGliY3VybC83LjE5LjcgT3BlblNTTC8wLjkuOGogemxpYi8xLjIuNyBsaWJpZG4vMS4xMCIJIi0iCVRMU3YxCURIRS1SU0EtQUVTMjU2LVNIQQkiLSQtIgkrCTc5NjEJInByb3h5Omh0dHA6Ly8xMC4yNDUuMTAuNDUvcGxzL2FwZXgvZj9wPTEwNToxOjA6Ojo6OiIifScgLUggIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg=="}' -H "Content-Type: application/json"
# (%{DATE:datum})?\s*(%{TIME:cas})?\s*(%{WORD:status_kod})?\s*(%{IP:vzdalena_ip})?:(%{WORD:vzdaleny_port})?\s*(%{QS:cn})?\s*(%{WORD:request_method})?\s*\"(%{URIPATHPARAM:pozadovana_url})?\"\s*(%{QS:query_string})?\s*(%{IP:lokalni_ip})?:(%{WORD:lokalni_port})?\s*\"(%{JAVACLASS:server_name})?\"\s*HTTP(%{URIPATHPARAM:http_protokol})?\s*(%{INT:request_vel})?\s*(%{INT:responese_vel})?\s*(%{INT:zpracovani_cas})?\s*(%{QS:referer})?\s*(%{QS:user_agent})?\s*(%{QS:cookies})?\s*(%{WORD:ssl_protokol})?\s*(%{USERNAME:ssl_cipher_suit})?\s*(%{QS:certifikat})?\s*(%{DATA:status_spojeni})?\s*(%{INT:proces_id})?\s*(%{QS:soubor})?"


# docker build -t logger:latest .
# docker tag logger:latest localhost:5000/logger:latest
# docker push localhost:5000/logger:latest