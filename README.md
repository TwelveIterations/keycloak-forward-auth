# Keycloak Forward Auth

This plugin adds a new forward-auth endpoint to Keycloak that can be used with Traefik's forward-auth middleware.

It works by checking for a special cookie to be present (`{clientId}_forward_auth`) and contain a valid access token for this client. If not, a redirect to the login page is performed, which will subsequently set said cookie after login. If the cookie already exists and is still valid, 204 NO CONTENT is returned and Traefik will let the request pass through the middleware.

## Work in Progress

- The plugin does not attempt to refresh access tokens currently, which means it will perform an unnecessary auth redirect when navigating after the access token expired. See [ForwardAuthResource#refreshCookie](https://github.com/TwelveIterations/keycloak-forward-auth/blob/main/src/main/java/com/audiorole/keycloak/forwardauth/ForwardAuthResource.java#L174).