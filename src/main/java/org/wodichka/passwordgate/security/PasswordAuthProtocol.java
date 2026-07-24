package org.wodichka.passwordgate.security;

import java.math.BigInteger;

public interface PasswordAuthProtocol {
    Registration createRegistration(byte[] identity, char[] password);
    Registration createRegistration(byte[] identity, char[] password, byte[] salt);
    ClientExchange startClient(byte[] identity, char[] password, byte[] salt, BigInteger serverPublic);
    ServerExchange startServer(BigInteger verifier);

    record Registration(byte[] salt, BigInteger verifier) {}
    interface ClientExchange extends AutoCloseable {
        BigInteger publicValue(); byte[] clientProof(); boolean verifyServerProof(byte[] proof); @Override void close();
    }
    interface ServerExchange extends AutoCloseable {
        BigInteger publicValue(); byte[] verifyClient(BigInteger clientPublic, byte[] clientProof); @Override void close();
    }
}
