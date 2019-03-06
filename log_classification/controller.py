import base64
import datetime
import json
import os
import time

import psycopg2.extensions
import requests
from api_security import require_appkey
from bo.network_dao import get_network
from configuration.app_config import app, ns, api, api_port, debug_server
from data_preparator import prepare_data, prepare_log_row
from flask import abort
from flask import jsonify, request
from flask_restful_swagger import swagger
from flask_restplus import Resource
from network_model import load_trained_model, predict
from requests.packages import package

psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)


@ns.route('/swagger2.json')
class ApiDocsController(Resource):
    def get(self):
        with app.app_context():
            schema = api.__schema__
            schema['basePath'] = os.environ['API_URI']
            return jsonify(schema)


@ns.route('/healtz')
class HealthController(Resource):
    '''Check if app is running and know its id'''

    @swagger.operation()
    def get(self):
        network = get_network(network_id)
        if network is not None:
            return jsonify("true")


@ns.route('/network/predict')
class NetworkController(Resource):
    '''Classify based on user input'''

    post_parser = api.parser()
    post_parser.add_argument('Authorization', type=str, location='headers', required=True)
    post_parser.add_argument("data", type=package, location="json")

    # post_parser.add_argument('file', location='files',type=FileStorage, required=True)

    @api.expect(post_parser, validate=True)
    @require_appkey
    def post(self):
        data = {"success": False}

        input_data, additional_data = self.get_request_data(request)
        if input_data is not None:

            classification = predict(input_data, additional_data)
            data["main_class"] = classification
            ts = time.time()
            data['timestamp'] = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            data["success"] = True
            data['user_request'] = input_data
            main_label = data["main_class"]

            network = get_network(network_id)
            data = self.call_modules(network, main_label, data)
        else:
            abort(400)

        return jsonify(data)

    def get_request_data(self, request):
        input_data = request.json

        if input_data is not None and 'message' in input_data:
            data = input_data['message']
            decoded_log = base64.b64decode(str(data))
            parsed_data = prepare_log_row(decoded_log, pattern)
            if 'message_context' in input_data:
                return parsed_data, input_data['message_context']

            return parsed_data, None

        return None

    def call_modules(self, network, main_label, data):
        for module in network.modules:
            if module.response_class == main_label and module.status == 4:
                headers = {"Authorization": module.api_key, "Secret": module.network.user.secret}

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


def configure_network():
    global network_id
    network_id = os.environ['NETWORK_ID']
    network = get_network(network_id)
    load_trained_model(network)


if __name__ == "__main__":
    configure_network()
    app.run(debug=debug_server, host="0.0.0.0", port=api_port)

# one_row = '2016-06-04	12:00:09	200	94.199.43.237:25689	"-"	GET	"/wwwstats/f"	"?p=105:1:0:::::"	10.245.8.60:443	"www.czechpoint.cz"	HTTP/1.1	592	28765	45877	"-"	"curl/7.19.7 (x86_64-suse-linux-gnu) libcurl/7.19.7 OpenSSL/0.9.8j zlib/1.2.7 libidn/1.10"	"-"	TLSv1	DHE-RSA-AES256-SHA	"-$-"	+	7961	"proxy:http://10.245.10.45/pls/apex/f?p=105:1:0:::::"'
# curl -X POST "localhost:5001/network/predict"  -H "accept: application/json" -H "Authorization: eyJuZXR3b3JrX2lkIjoxMDcsImFwaV9rZXkiOiJTbFJYYW1WU1dWQnhVMDlLVkVsT1RscG1XR0pvVFdsdVltTlJPVzlVYTJzPSJ9" -H "Secret: eyJzZWNyZXQiOiJkR0ZxYm1WZmFHVnpiRzg9In0=" --data '{"message":"2016-06-04	12:00:09	200	94.199.43.237:25689	"-"	GET	"/wwwstats/f"	"?p=105:1:0:::::"	10.245.8.60:443	"www.czechpoint.cz"	HTTP/1.1	592	28765	45877	"-"	"curl/7.19.7 (x86_64-suse-linux-gnu) libcurl/7.19.7 OpenSSL/0.9.8j zlib/1.2.7 libidn/1.10"	"-"	TLSv1	DHE-RSA-AES256-SHA	"-$-"	+	7961	"proxy:http://10.245.10.45/pls/apex/f?p=105:1:0:::::""}' -H "Content-Type: application/json"
# curl -X POST "localhost:5001/network/predict"  -H "accept: application/json" -H "Authorization: eyJuZXR3b3JrX2lkIjoxMDcsImFwaV9rZXkiOiJTbFJYYW1WU1dWQnhVMDlLVkVsT1RscG1XR0pvVFdsdVltTlJPVzlVYTJzPSJ9" -H "Secret: eyJzZWNyZXQiOiJkR0ZxYm1WZmFHVnpiRzg9In0=" --data '{"message":"MjAxNi0wNi0wNAkxMjowMDowOQkyMDAJOTQuMTk5LjQzLjIzNzoyNTY4OQkiLSIJR0VUCSIvd3d3c3RhdHMvZiIJIj9wPTEwNToxOjA6Ojo6OiIJMTAuMjQ1LjguNjA6NDQzCSJ3d3cuY3plY2hwb2ludC5jeiIJSFRUUC8xLjEJNTkyCTI4NzY1CTQ1ODc3CSItIgkiY3VybC83LjE5LjcgKHg4Nl82NC1zdXNlLWxpbnV4LWdudSkgbGliY3VybC83LjE5LjcgT3BlblNTTC8wLjkuOGogemxpYi8xLjIuNyBsaWJpZG4vMS4xMCIJIi0iCVRMU3YxCURIRS1SU0EtQUVTMjU2LVNIQQkiLSQtIgkrCTc5NjEJInByb3h5Omh0dHA6Ly8xMC4yNDUuMTAuNDUvcGxzL2FwZXgvZj9wPTEwNToxOjA6Ojo6OiIifScgLUggIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg=="}' -H "Content-Type: application/json"
# (%{DATE:datum})?\s*(%{TIME:cas})?\s*(%{WORD:status_kod})?\s*(%{IP:vzdalena_ip})?:(%{WORD:vzdaleny_port})?\s*(%{QS:cn})?\s*(%{WORD:request_method})?\s*\"(%{URIPATHPARAM:pozadovana_url})?\"\s*(%{QS:query_string})?\s*(%{IP:lokalni_ip})?:(%{WORD:lokalni_port})?\s*\"(%{JAVACLASS:server_name})?\"\s*HTTP(%{URIPATHPARAM:http_protokol})?\s*(%{INT:request_vel})?\s*(%{INT:responese_vel})?\s*(%{INT:zpracovani_cas})?\s*(%{QS:referer})?\s*(%{QS:user_agent})?\s*(%{QS:cookies})?\s*(%{WORD:ssl_protokol})?\s*(%{USERNAME:ssl_cipher_suit})?\s*(%{QS:certifikat})?\s*(%{DATA:status_spojeni})?\s*(%{INT:proces_id})?\s*(%{QS:soubor})?"


# docker build -t logger:latest .
# docker tag logger:latest localhost:5000/logger:latest
# docker push localhost:5000/logger:latest
