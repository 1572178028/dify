#coding:UTF-8
"""
Requirements:
    1. Flask >= 0.10.1
    2. requests
    3. jwkest >= 1.1.7

Usage:
    python oidc_code_demo.py -H {listen_address} -p {listen_port}

Help:
    python oidc_code_demo.py -h
"""
import datetime
import json
import uuid
from hashlib import md5
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session
from jwt_compat import JWS, NoSuitableSigningKeys, SYMKey, load_jwks_from_url

from libs.helper import extract_remote_ip
from services.account_service import AccountService

__revision__ = "0.01"
__author__ = "chenxs@corp.netease.com"

OIDC_CLIENT_ID = "4c055a10660f11f09d5c0242ac120002"
OIDC_CLIENT_SECRET = "81ee34b5665f4157b965de7b2c6501624c055d30660f11f09d5c0242ac120002"
OIDC_PROVIDER = "https://login.netease.com/connect"
OIDC_AUTHORIZATION_SERVER = "https://login.netease.com/connect/authorize"
OIDC_TOKEN_ENDPOINT = "https://login.netease.com/connect/token"
OIDC_USERINFO_ENDPOINT = "https://login.netease.com/connect/userinfo"
OIDC_SCOPE = "openid nickname email fullname dep title empno"
OIDC_REDIRECT_URI = "https://dify.miaode.com:5000/finish"
OIDC_JWKS_URI = "https://login.netease.com/connect/jwks"
OIDC_ALG = "HS256"

PYTHON_OIDC_DEMO = Flask(__name__)

@PYTHON_OIDC_DEMO.route("/", methods=['GET'])
def index():
    """index"""
    if 'username' in session:
        body = (
                   "</br><h2>OpenID Connect 登录成功！</h2></br>"
                   "您的用户名是：%s</br>"
                   "您的姓名是：%s</br>"
                   "您的邮箱是：%s</br>"
                   "您的职位是：%s</br>"
                   "您的部门是：%s</br>"
                   "您的工号是：%s</br>") % (
                   session['username'], session.get('fullname', ''),
                   session.get('email', ''), session.get('title', ''),
                   session.get('dep', ''), session.get('empno', ''))
        body += "<a href='/login'>我要重新登录</a>"
        return body
    else:
        return "<a href='/login'>我要登录</a>"


@PYTHON_OIDC_DEMO.route("/login", methods=['GET'])
def login():
    """AuthN Request"""
    session.clear()
    now = datetime.datetime.now().strftime("%s")
    session['uid'] = uuid.uuid4().hex
    session['state'] = session['uid']
    session['nonce'] = md5((session['uid'] + now).encode('utf-8')).hexdigest()

    authn_request_params = {
        'response_type': 'code',
        'client_id': OIDC_CLIENT_ID,
        'state': session['state'],
        'nonce': session['nonce'],
        'scope': OIDC_SCOPE,
        'redirect_uri': OIDC_REDIRECT_URI,
        #'prompt': 'login',
        'display': 'touch',
    }

    redirect_url = "?".join([
        OIDC_AUTHORIZATION_SERVER, urlencode(authn_request_params)])

    return redirect(redirect_url)


def token_request(code):
    """2. Token Request"""
    params = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': OIDC_REDIRECT_URI,
        'client_id': OIDC_CLIENT_ID,
        'client_secret': OIDC_CLIENT_SECRET,
    }
    _resp = requests.post(OIDC_TOKEN_ENDPOINT, data=params)
    return json.loads(_resp.text)


def id_token_verify(id_token, nonce=None):
    """3. id token verify"""
    now = int(datetime.datetime.now().strftime("%s"))

    if OIDC_ALG == "HS256":
        signed_keys = [SYMKey(key=OIDC_CLIENT_SECRET)]
    else:
        signed_keys = load_jwks_from_url(OIDC_JWKS_URI)

    try:
        # 使用修复后的 verify_compact
        plain_id_token = JWS().verify_compact(id_token, signed_keys, OIDC_ALG)
    except NoSuitableSigningKeys as e:
        print(f"JWT 签名验证失败: {e}")
        return {'error': 'can not verify the id token'}
    except Exception as e:
        print(f"JWT 验证异常: {type(e).__name__} - {e}")
        return {'error': f'JWT 验证异常: {e}'}


    # 业务逻辑验证
    if nonce:
        if ('nonce' not in plain_id_token) or (plain_id_token['nonce'] != nonce):
            return {'error': 'id token nonce not correct'}

    if plain_id_token['iss'] != OIDC_PROVIDER:
        return {'error': 'id token iss not correct'}

    if plain_id_token['aud'] != OIDC_CLIENT_ID:
        return {'error': 'id token aud not correct'}

    if now >= int(plain_id_token['exp']):
        return {'error': 'id token expired'}

    print("所有验证都通过!")
    return {'id_token': plain_id_token}

@PYTHON_OIDC_DEMO.route("/finish", methods=['GET'])
def finish():
    """
    1. AuthN Response
    2. Token Request
    3. id token verify
    4. userinfo request
    5. login user
    """

    # 1. AuthN Response
    try:
        code = request.args.get('code')
        if session.get('state'):
            state = request.args.get('state')
            if state != session['state']:
                print(f"State 验证失败: 期望 {session['state']}, 实际 {state}")
                return "非法请求"
            else:
                print("✅ State 验证通过")
    except Exception as e:
        print(f"AuthN Response 处理失败: {e}")
        return "非法请求"

    # 2. Token Request
    token = token_request(code)
    if 'error' in token:
        return "出错啦%s" % str(token)
    # 3. id token verify
    id_token_verified = id_token_verify(token['id_token'], session.get('nonce'))
    if 'error' in id_token_verified:
        return id_token_verified['error']
    else:
        id_token = id_token_verified['id_token']
        print("ID Token 验证成功")

    # 4. userinfo request
    _req_session = requests.Session()
    _req_session.headers.update({
        "Authorization": "Bearer %s" % token['access_token']})
    userinfo_req = _req_session.get(OIDC_USERINFO_ENDPOINT)
    userinfo = json.loads(userinfo_req.text)

    # 5. login the user
    session['username'] = userinfo['nickname']
    session['email'] = userinfo['email']
    session['title'] = userinfo.get('title', '')
    session['empno'] = userinfo.get('empno', '')
    session['dep'] = userinfo.get('dep', '')
    session['fullname'] = userinfo.get('fullname', '')
    account = AccountService.authenticateOpenId(userinfo['email'],userinfo['nickname'])
    token_pair = AccountService.login(account=account, ip_address=extract_remote_ip(request))
    return redirect("http://localhost:3000/apps")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(usage='%(prog)s [options]')
    parser.add_argument('--version', action='version', version='%(prog)s ' + str(__revision__))
    parser.add_argument(
        '-H', '--host', dest='host', type=str,
        help="Specify listening adress, default is 127.0.0.1")
    parser.add_argument(
        '-p', '--port', dest='port', type=int,
        help="Specify listening port, default is 5000")
    parser.add_argument(
        '-c', '--client_id', dest='client_id', type=str,
        help="oidc client_id is required.")
    parser.add_argument(
        '-s', '--client_secret', dest='client_secret', type=str,
        help="oidc client_secret is required.")

    args = parser.parse_args()

    host = args.host or 'dify.miaode.com'
    port = args.port or 5001
    OIDC_REDIRECT_URI = "http://%s:%s/finish" % (host, port)
    # OIDC_CLIENT_ID = args.client_id
    # OIDC_CLIENT_SECRET = args.client_secret
    # if not OIDC_CLIENT_ID or not OIDC_CLIENT_SECRET:
    #     parser.print_help()
    #     parser.exit()
    PYTHON_OIDC_DEMO.secret_key = "this is a random secret"
    PYTHON_OIDC_DEMO.debug = True
    PYTHON_OIDC_DEMO.run(host=host, port=port)
