from flask import jsonify
from flask_jwt_extended import create_access_token
import logging
import requests

from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user

def exentriqLoginByToken(token, sm, sso_url):
    if not token:
        return {"result":False, "msg": "Missing token parameter"}

    req_payload = {'token': token}
    # r = requests.get('http://37.187.137.141:1880/86260/login', params=req_payload)
    r_payload = { 'id': '', 'method': 'auth.loginBySessionToken', 'params': [token] }

    r = requests.post(sso_url, json=r_payload)
    payload = r.json()

    logging.debug(payload)

    p_result = payload['result']

    if p_result == None:
        return {"result":False, "error": "Bad token"}

    p_username = p_result['username']

    user = sm.find_user(username=p_username)
    logging.debug(user)
    logging.debug(sm.role_model)
    if user == None:

        first_name = ''
        last_name = ''
        email = ''
        if 'firstName' in p_result:
            first_name = p_result['firstName']
        if 'lastName' in p_result:
            last_name = p_result['lastName']
        if 'email' in p_result:
            email = p_result['email']
        role = sm.find_role('Gamma')
        sm.add_user(p_username, first_name, last_name, email, role)

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=p_username)
    return {'result':True, 'access_token':access_token, 'username': p_username} # jsonify(result=True, access_token=access_token, username=p_username), 200

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        redirect_url = self.appbuilder.get_url_for_index
        if request.args.get('redirect') is not None:
            redirect_url = request.args.get('redirect')

        if request.args.get('token') is not None:
            sso_url = self.appbuilder.app.config['EXENRIQ_SSO_URL']
            login_result = exentriqLoginByToken(request.args.get('token'), self.appbuilder.sm, sso_url)
            if login_result['result'] == True:
                user = self.appbuilder.sm.find_user(username=login_result['username'])
            login_user(user, remember=False)
            return redirect(redirect_url)
        elif g.user is not None and g.user.is_authenticated():
            return redirect(redirect_url)
        else:
            flash('Unable to auto login', 'warning')
            return super(CustomAuthDBView,self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
