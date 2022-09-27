# ckanext-restricted-access

Extension for restricting access to CKAN (API) actions.

Adds a middleware layer to intercept requests and check them against a list of restricted actions.

The benefit of implementing it this way rather than say using chained action or auth functions is that you don't have to create an override for every action or auth that you want to restrict.

__Note:__ this extension currently only restricts actions to sysadmin level users.

## Example

We have two CKAN instances: one private, the other public.

The public instance harvests from the private instance daily.

The harvest source configuration on the public instance contains the API key of a user on the private instance.

The `harvest_source_list` API action in `ckanext-harvest` exposes the full configuration of the harvest source, including the API key.

This is a security risk for us - therefore we want to restrict the `harvest_source_list` API action to `sysadmin` authenticated users.

 ## Configuration
 
Added the `restricted_access` plugin to your CKAN `.ini` file, e.g.
 
    ckan.plugins = ... restricted_access ...

Add two new settings to your CKAN `.ini` file:

    ckan.restricted.api_actions = harvest_source_list user_autocomplete status_show
    ckan.restricted.ui_paths = user.register resource.download

Both are a space separated list of API actions and UI endpoints that will be restricted to `sysadmin` level users.

If you want to close the site for anon users, add this setting to your CKAN `.ini` file:

    ckan.restricted.redirect_anon_to_login = true

The default value is `False`
