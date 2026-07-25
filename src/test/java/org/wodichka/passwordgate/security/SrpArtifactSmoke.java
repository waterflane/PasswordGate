package org.wodichka.passwordgate.security;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class SrpArtifactSmoke {
    private SrpArtifactSmoke() {}

    public static void main(String[] args) {
        byte[] identity = "artifact-smoke".getBytes(StandardCharsets.UTF_8);
        char[] password = "Correct horse battery staple!7".toCharArray();
        PasswordAuthProtocol protocol = new Srp6aProtocol();
        PasswordAuthProtocol.ServerExchange server = null;
        PasswordAuthProtocol.ClientExchange client = null;
        try {
            PasswordAuthProtocol.Registration registration = protocol.createRegistration(identity, password);
            server = protocol.startServer(registration.verifier());
            client = protocol.startClient(identity, password, registration.salt(), server.publicValue());
            byte[] proof = server.verifyClient(client.publicValue(), client.clientProof());
            if (proof == null || !client.verifyServerProof(proof)) throw new AssertionError("SRP artifact smoke test failed");
        } finally {
            if (client != null) client.close();
            if (server != null) server.close();
            Arrays.fill(password, '\0');
        }
    }
}
