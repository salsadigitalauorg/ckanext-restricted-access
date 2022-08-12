import json
import logging

from six.moves.urllib.parse import urlparse

import ckan.authz as authz
import ckan.plugins.toolkit as toolkit

from ckan.lib import base


log = logging.getLogger(__name__)

not_found_message = (
    'The requested URL was not found on the server. '
    'If you entered the URL manually please check your spelling and try again.'
)


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
    restricted_ui_paths = toolkit.config.get('ckan.restricted.ui_paths', "").split()
    if toolkit.request.endpoint in restricted_ui_paths:
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
    restricted_api_actions = toolkit.config.get('ckan.restricted.api_actions', [])
    if api_action in restricted_api_actions:
        if not api_user or not authz.is_sysadmin(api_user):
            return False
    return True


def ckanext_before_request():
    response = None

    api_action = toolkit.request.view_args.get('logic_function', None)
    username = toolkit.g.user

    if api_action:
        # Dealing with API requests
        # if the request is an api action, check against restricted actions
        if not check_access_api_action(username, api_action):
            return unauthorised_api_response().encode('utf8')

    # Dealing with UI requests
    if not check_access_ui_path(username):
        return base.abort(404, toolkit._(not_found_message))

    return response


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
