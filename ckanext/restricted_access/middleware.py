import json
import six
import logging

from six.moves.urllib.parse import urlparse

import ckan.authz as authz
import ckan.model as model
import ckan.lib.api_token as api_token
import ckan.plugins.toolkit as toolkit

from ckan.common import _, config, request
from ckan.lib import base


log = logging.getLogger(__name__)

not_found_message = (
    'The requested URL was not found on the server. '
    'If you entered the URL manually please check your spelling and try again.'
)


def get_api_action(environ):
    '''
    Checks the environ object to see if the request contains an api_action
    :param environ:
    :return: string of API action, or None
    '''
    api_action = None
    parsed = urlparse(environ.get('PATH_INFO', ''))
    paths = parsed.path.split('/')
    # api action urls are either /api/action/<action_name> or /api/<version>/action/<action_name>
    if paths and 'api' in paths and 'action' in paths:
        # action should always be the last path
        api_action = paths[len(paths)-1]
        
    return api_action


def check_access_ui_path(username):
    '''
    Check an endpoint against a list of restricted paths set in the CKAN `.ini` file
    :param repoze_who_identity:
    :param username:
    :param ui_path:
    :return:
    '''
    # TODO: Improve this to handle wildcards such as /user/salsa ...
    # ...(without restricting /user/XYZ/edit when required).
    restricted_ui_paths = config.get('ckan.restricted.ui_paths', "").split()
    if request.endpoint in restricted_ui_paths:
        if not username or not authz.is_sysadmin(username):
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
    restricted_api_actions = config.get('ckan.restricted.api_actions', [])
    if api_action in restricted_api_actions:
        if not api_user or not authz.is_sysadmin(api_user.name):
            return False
    return True


def get_username(environ):
    '''
    if ckan_version >= 2.10 we are getting the user from flask_login current_user proxy

    if ckan_version <= 2.9 we are getting the user from Repoze.who framework
    '''
    if toolkit.check_ckan_version(min_version='2.10'):
        from ckan.common import current_user
        username = current_user.name
    else:
        username = environ.get('REMOTE_USER', None)

    return username


def ckanext_before_request():
    response = None

    api_action = get_api_action(request.environ)

    if api_action:
        # Dealing with API requests
        # if the request is an api action, check against restricted actions
        api_user = _get_user_for_apikey(request.environ)
        if not check_access_api_action(api_user, api_action):
            return unauthorised_api_response().encode('utf8')

    # Dealing with UI requests
    username = get_username(request.environ)
    if not check_access_ui_path(username):
        return base.abort(404, _(not_found_message))

    return response


def _get_user_for_apikey(environ):
    '''
    This code was copied from core CKAN and was added to allow 
    attempt to find a CKAN user from potential API key/API token provided in environ object
    :param environ:
    :return: user object or None
    '''
    apikey_header_name = config.get(base.APIKEY_HEADER_NAME_KEY,
                                    base.APIKEY_HEADER_NAME_DEFAULT)
    apikey = environ.get(apikey_header_name, '')
    if not apikey:
        # For misunderstanding old documentation (now fixed).
        apikey = environ.get(u'HTTP_AUTHORIZATION', u'')
    if not apikey:
        apikey = environ.get(u'Authorization', u'')
        # Forget HTTP Auth credentials (they have spaces).
        if u' ' in apikey:
            apikey = u''
    if not apikey:
        return None
    apikey = six.ensure_text(apikey, errors=u"ignore")
    query = model.Session.query(model.User)
    user = query.filter_by(apikey=apikey).first()

    if not user:
        user = api_token.get_user_from_token(apikey)
    return user


def unauthorised_api_response():
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
