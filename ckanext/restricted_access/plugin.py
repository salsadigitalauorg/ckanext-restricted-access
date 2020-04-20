import ckan.plugins as plugins
import middleware


class RestrictedAccessPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IMiddleware, inherit=True)

    def make_middleware(self, app, config):
        return middleware.AuthMiddleware(app, config)
