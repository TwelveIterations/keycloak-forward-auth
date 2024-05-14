package com.audiorole.keycloak.forwardauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.common.util.Base64;
import org.keycloak.connections.httpclient.HttpClientBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class ForwardAuthResource {

    private final KeycloakSession session;
    private final ObjectMapper mapper = new ObjectMapper();

    public ForwardAuthResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    public Response entrypoint(@QueryParam("client_id") String clientId) {
        if (clientId == null || clientId.isEmpty()) {
            return ErrorResponse.error("Missing client id", Response.Status.BAD_REQUEST);
        }

        URI requestUri = getOriginalRequestUri();
        if (requestUri.getPath().endsWith("/forward-auth/callback")) {
            String code = null;
            String state = null;
            List<NameValuePair> params = URLEncodedUtils.parse(requestUri, StandardCharsets.UTF_8);
            for (NameValuePair param : params) {
                switch (param.getName()) {
                    case "code":
                        code = param.getValue();
                        break;
                    case "state":
                        state = param.getValue();
                        break;
                }
            }
            return handleCallback(code, state);
        }

        Set<String> authCookies = CookieHelper.getCookieValue(getAuthCookieName(clientId));

        if (!validateCookie(authCookies, clientId)) {
            Set<String> authRefreshCookies = CookieHelper.getCookieValue(getAuthRefreshCookieName(clientId));
            if (!refreshCookie(authRefreshCookies, clientId)) {
                return authRedirect(clientId);
            }
        }

        return Response.noContent().build();
    }

    public Response handleCallback(String code, String state) {
        if (code == null || code.isEmpty()) {
            return ErrorResponse.error("Missing code", Response.Status.BAD_REQUEST);
        }

        if (state == null || state.isEmpty()) {
            return ErrorResponse.error("Missing state", Response.Status.BAD_REQUEST);
        }

        String clientId;
        String redirectUri;
        try {
            String[] decodedState = decodeState(state);
            clientId = decodedState[0];
            redirectUri = decodedState[1];
        } catch (IOException e) {
            return ErrorResponse.error("Invalid state", Response.Status.BAD_REQUEST);
        }

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !client.isEnabled()) {
            return ErrorResponse.error("Client not found or disabled", Response.Status.BAD_REQUEST);
        }

        KeycloakUriInfo uriInfo = session.getContext().getUri();
        URI tokenUrl = uriInfo.getBaseUriBuilder()
                .path("realms")
                .path(realm.getName())
                .path("protocol")
                .path("openid-connect")
                .path("token")
                .build();

        String accessToken = null;
        try (CloseableHttpClient httpClient = new HttpClientBuilder().build()) {
            HttpPost post = new HttpPost(tokenUrl);
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", code));
            params.add(new BasicNameValuePair("secret", client.getSecret()));
            params.add(new BasicNameValuePair("client_id", clientId));
            params.add(new BasicNameValuePair("redirect_uri", getCallbackRedirectUri().toString()));
            post.setEntity(new UrlEncodedFormEntity(params));
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                String responseString = EntityUtils.toString(response.getEntity());
                JsonNode node = mapper.readTree(responseString);
                String cookiePath = "/";
                if (node.has("access_token")) {
                    accessToken = node.get("access_token").asText();
                    CookieHelper.addCookie(getAuthCookieName(clientId), accessToken, cookiePath, null, null, 86400, true, true);
                }
                if (node.has("refresh_token")) {
                    String refreshToken = node.get("refresh_token").asText();
                    CookieHelper.addCookie(getAuthRefreshCookieName(clientId), refreshToken, cookiePath, null, null, 86400, true, true);
                }
            }
        } catch (IOException e) {
            return ErrorResponse.error("Internal server error", Response.Status.INTERNAL_SERVER_ERROR);
        } catch (URISyntaxException e) {
            return ErrorResponse.error("Invalid forwarded request uri", Response.Status.BAD_REQUEST);
        }

        if (!validateToken(accessToken, clientId)) {
            return ErrorResponse.error("Invalid token", Response.Status.UNAUTHORIZED);
        }

        return Response.status(Response.Status.FOUND).location(URI.create(redirectUri)).build();
    }

    private boolean validateCookie(Set<String> authCookies, String clientId) {
        for (String authCookie : authCookies) {
            if (validateToken(authCookie, clientId)) {
                return true;
            }
        }
        return false;
    }

    private boolean validateToken(String token, String clientId) {
        if (token == null) {
            return false;
        }

        AppAuthManager.BearerTokenAuthenticator authenticator = new AppAuthManager.BearerTokenAuthenticator(session)
                .setTokenString(token)
                .setAudience(clientId);
        AuthenticationManager.AuthResult authResult = authenticator.authenticate();
        return authResult != null;
    }

    private boolean refreshCookie(Set<String> authRefreshCookies, String clientId) {
        for (String authRefreshCookie : authRefreshCookies) {
            // TODO refresh
        }
        return false;
    }

    private Response authRedirect(String clientId) {
        try {
            String forwardedMethod = session.getContext().getRequestHeaders().getHeaderString("X-Forwarded-Method");
            if (!forwardedMethod.equalsIgnoreCase("GET")) {
                return ErrorResponse.error("Unauthorized " + forwardedMethod, Response.Status.UNAUTHORIZED);
            }
        } catch (Exception ignored) {
        }

        try {
            String nonce = createNonce();
            String state = createState(clientId);
            URI redirectUri = getCallbackRedirectUri();
            URI loginUrl = getAuthorizeUri(clientId, nonce, state, redirectUri);
            return Response.status(Response.Status.FOUND).location(loginUrl).build();
        } catch (URISyntaxException e) {
            return ErrorResponse.error("Invalid forwarded request uri", Response.Status.BAD_REQUEST);
        }
    }

    private URI getAuthorizeUri(String clientId, String nonce, String state, URI redirectUri) {
        return session.getContext().getUri().getBaseUriBuilder()
                .path("realms")
                .path(session.getContext().getRealm().getName())
                .path("protocol")
                .path("openid-connect")
                .path("auth")
                .queryParam("nonce", nonce)
                .queryParam("state", state)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", "openid")
                .queryParam("response_type", "code")
                .build();
    }

    private URI getOriginalRequestUri() {
        String forwardedProto = session.getContext().getRequestHeaders().getHeaderString("X-Forwarded-Proto");
        String forwardedHost = session.getContext().getRequestHeaders().getHeaderString("X-Forwarded-Host");
        String forwardedUri = session.getContext().getRequestHeaders().getHeaderString("X-Forwarded-Uri");
        if (forwardedUri == null) {
            forwardedUri = "/realms/" + session.getContext().getRealm().getName();
        }
        return URI.create(forwardedProto + "://" + forwardedHost + forwardedUri);
    }

    private URI getCallbackRedirectUri() throws URISyntaxException {
        URI originalRequestUri = getOriginalRequestUri();
        String path = originalRequestUri.getPath();
        if (!path.endsWith("/forward-auth/callback")) {
            if (!path.endsWith("/")) {
                path += "/";
            }
            path += "forward-auth/callback";
        }
        return new URI(originalRequestUri.getScheme(), originalRequestUri.getHost(), path, null);
    }

    private String createNonce() {
        return UUID.randomUUID().toString();
    }

    private String[] decodeState(String state) throws IOException {
        String decoded = new String(Base64.decode(state), StandardCharsets.UTF_8);
        return decoded.split("\\|");
    }

    private String createState(String clientId) throws URISyntaxException {
        URI postLoginRedirectUri = getOriginalRequestUri();
        String state = clientId + "|" + postLoginRedirectUri;
        return Base64.encodeBytes(state.getBytes(StandardCharsets.UTF_8));
    }

    private String getAuthRefreshCookieName(String clientId) {
        return clientId + "_forward_auth_refresh";
    }

    private String getAuthCookieName(String clientId) {
        return clientId + "_forward_auth";
    }
}
