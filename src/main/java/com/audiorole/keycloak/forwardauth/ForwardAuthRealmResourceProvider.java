package com.audiorole.keycloak.forwardauth;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class ForwardAuthRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public ForwardAuthRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new ForwardAuthResource(session);
    }

    @Override
    public void close() {

    }
}
