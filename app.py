import flask, base64, requests, jwt, json

from flask import request
from flask_restful import Api, Resource, reqparse

app = flask.Flask(__name__)

endpoint_base="https://sso-dev.apps.banestes.b.br/auth"
endpoint_authorization=endpoint_base+"/realms/sfb-dev/protocol/openid-connect/auth"
endpoint_token=endpoint_base+"/realms/sfb-dev/protocol/openid-connect/token"

client_id="zenvia-gerenciador-web"
client_secret="7835cd41-71fb-4f2c-832c-cc71d2ca6adc"
redirect_uri="https://openid-poc.herokuapp.com/return"

@app.route("/")
def index():
    return "OPEN ID CONNECT HOMEPAGE", 200

@app.route("/auth")
def auth():
    print("Redirecting...")
    url_redirect=(endpoint_authorization +
                "?response_type=code" +
                "&scope=openid" +
                "&client_id=zenvia-gerenciador-web" +
                "&state=af0ifjsldkj" +
                "&redirect_uri=" + redirect_uri)
    return flask.redirect(url_redirect)

@app.route("/return")
def ret():
    state = request.args.get('state')
    session_state = request.args.get('session_state')
    code = request.args.get('code')

    auth=requests.auth.HTTPBasicAuth(client_id, client_secret)

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri' : redirect_uri
    }

    resp = requests.post(endpoint_token, data, auth=auth, verify=False)
    print("Resposta recebida: {} - {}".format(resp, resp.text))

    if resp.status_code == 200:
        j = resp.json()
        #print("id_token coded: {}".format(j['id_token']))
        id_token_headers = jwt.get_unverified_header(j['id_token'])
        print("unverified_headers: {}".format(id_token_headers))
        #id_token = jwt.decode(j['id_token'], client_secret, algorithms=['RS256'])
        id_token = jwt.decode(j['id_token'], verify=False)
        print("id_token decoded: {}".format(id_token))
        result_string = json.dumps(id_token_headers, indent=2) + "<br/>" + json.dumps(id_token, indent=2)
        return result_string, 200

    return resp.text, resp.status_code

if __name__ == "__main__":
    app.run(debug=True)
