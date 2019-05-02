# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# pylint: disable=R
from flask import request, jsonify, g
from flask_appbuilder import expose
from flask_appbuilder.security.decorators import has_access_api
import simplejson as json

from superset import appbuilder, db, security_manager
from superset.common.query_context import QueryContext
from superset.legacy import update_time_range
import superset.models.core as models
from superset.models.core import Log
from superset.utils import core as utils
from .base import api, BaseSupersetView, handle_api_exception

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_current_user
)

from flask_appbuilder.models.sqla.interface import SQLAInterface
import logging
import requests
from superset.exentriq import exentriqLoginByToken

#from flask_appbuilder.api import ModelRestApi
#from flask_appbuilder.models.sqla.interface import SQLAInterface


class Api(BaseSupersetView):
    @Log.log_this
    @api
    @handle_api_exception
    @has_access_api
    @expose('/v1/query/', methods=['POST'])
    def query(self):
        """
        Takes a query_obj constructed in the client and returns payload data response
        for the given query_obj.
        params: query_context: json_blob
        """
        query_context = QueryContext(**json.loads(request.form.get('query_context')))
        security_manager.assert_datasource_permission(query_context.datasource)
        payload_json = query_context.get_payload()
        return json.dumps(
            payload_json,
            default=utils.json_int_dttm_ser,
            ignore_nan=True,
        )

    @Log.log_this
    @api
    @handle_api_exception
    @has_access_api
    @expose('/v1/form_data/', methods=['GET'])
    def query_form_data(self):
        """
        Get the formdata stored in the database for existing slice.
        params: slice_id: integer
        """
        form_data = {}
        slice_id = request.args.get('slice_id')
        if slice_id:
            slc = db.session.query(models.Slice).filter_by(id=slice_id).one_or_none()
            if slc:
                form_data = slc.form_data.copy()

        update_time_range(form_data)

        return json.dumps(form_data)

    @expose('/v1/custom/login', methods=['POST'])
    def login(self):
        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400
        token = request.json.get('token', None)
        sso_url = appbuilder.app.config['EXENRIQ_SSO_URL']
        result = exentriqLoginByToken(token, security_manager, sso_url);
        return jsonify(result);

    @expose('/v1/custom/dashboards', methods=['GET'])
    @jwt_required
    def dashboards(self):
        # Access the identity of the current user with get_jwt_identity
        #current_user_id = get_jwt_identity()
        #logging.debug(current_user_id)

        # Get user by username
        #user = security_manager.get_user_by_id(current_user_id)#find_user(username=current_user)
        #print(vars(user))

        user = get_current_user();

        # Check all_datasource_access access
        has_all_datasource_access = security_manager._has_view_access(user, 'all_datasource_access', 'all_datasource_access')
        logging.debug(has_all_datasource_access)

        Dash = models.Dashboard  # noqa
        User = security_manager.user_model

        if has_all_datasource_access == True:
            query = db.session.query(Dash)
        else:
            query = db.session.query(Dash).join(Dash.owners).filter(User.username == user.username)

        dashboards = []
        db_dashboards = query.all()
        for db_dashboard in db_dashboards:
            dashboards.append({'title':db_dashboard.dashboard_title, 'url':db_dashboard.url})
        return jsonify(dashboards)

    @expose('/v1/custom/test', methods=['GET'])
    @jwt_required
    def test(self):
        user = get_current_user();
        logging.debug(user)
        return jsonify(result='ok')

appbuilder.add_view_no_menu(Api)
