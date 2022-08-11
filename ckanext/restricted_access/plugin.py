import ckan.plugins as plugins
import ckanext.restricted_access.middleware as middleware


class RestrictedAccessPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IMiddleware, inherit=True)

    # IMiddleware

    def make_middleware(self, app, config):
        app.before_request(middleware.ckanext_before_request)
        return app
