import ckan.authz as authz
import ckan.model as model
import ckan.plugins.toolkit as toolkit
import json

from ckan.common import _, config
from ckan.lib import base


def get_api_action(environ):
    '''
    Checks the environ object to see if the request contains an api_action
    :param environ:
    :return: string of API action, or None
    '''
    routing_args = environ.get('wsgiorg.routing_args', None)

    if routing_args and routing_args[1] and routing_args[1].get('api_action', None):
        return routing_args[1].get('api_action')


def check_access_ui_path(repoze_who_identity, username, ui_path):
    '''
    Check a UI path (URI) against a list of restricted paths set in the CKAN `.ini` file
    :param repoze_who_identity:
    :param username:
    :param ui_path:
    :return:
    '''
    # @TODO: Improve this to handle wildcards such as /user/salsa (without restricting /user/XYZ/edit when required)
    restricted_ui_paths = config.get('ckan.restricted.ui_paths', []).split()
    if ui_path in restricted_ui_paths:
        if not repoze_who_identity or not username or not authz.is_sysadmin(username):
            return False
    return True


def check_access_api_action(api_user, api_action):
    '''
    Check an api_action against a list of restricted API actions
    :param api_user:
    :param api_action:
    :return: False if api_action is restricted and no user, or user not sysadmin, else True
    '''
    # @TODO: Improve this to handle wildcards such as `harvest_source*`
    restricted_api_actions = config.get('ckan.restricted.api_actions', []).split()
    if api_action in restricted_api_actions:
        if not api_user or not authz.is_sysadmin(api_user.name):
            return False
    return True


class AuthMiddleware(object):
    def __init__(self, app, app_conf):
        self.app = app

    def __call__(self, environ, start_response):
        api_action = get_api_action(environ)
        api_user = self._get_user_for_apikey(environ)
        repoze_who_identity = environ.get('repoze.who.identity', None)
        ui_path = environ.get('PATH_INFO', None)
        username = environ.get('REMOTE_USER', None)

        if not api_action:
            # Dealing with UI requests
            if not check_access_ui_path(repoze_who_identity, username, ui_path):
                status = "403 Forbidden"
                start_response(status, [])
                return ['<h1>Access Forbidden</h1> Path: %s' % ui_path]
        else:
            # Dealing with API requests
            # if the request is an api action, check against restricted actions
            if not check_access_api_action(api_user, api_action):
                start_response(200, [
                    ('Content-Type', 'application/json')
                ])
                return self.unauthorised_api_response()

        return self.app(environ, start_response)

    def _get_user_for_apikey(self, environ):
        '''
        Attempt to find a CKAN user from potential API key provided in environ object
        :param environ:
        :return: user object or None
        '''
        apikey_header_name = config.get(base.APIKEY_HEADER_NAME_KEY,
                                        base.APIKEY_HEADER_NAME_DEFAULT)
        apikey = environ.get(apikey_header_name, '')
        if not apikey:
            apikey = environ.get('HTTP_AUTHORIZATION', environ.get('Authorization', None))
        if apikey and ' ' not in apikey:
            apikey = unicode(apikey)
            query = model.Session.query(model.User)
            user = query.filter_by(apikey=apikey).first()
            return user

    def unauthorised_api_response(self):
        '''
        Simple helper function to return a JSON response message
        :return: JSON response
        '''
        response_msg = {
            'success': False,
            'error': {
                'message': 'Invalid request'
            }
        }
        return json.dumps(response_msg)
