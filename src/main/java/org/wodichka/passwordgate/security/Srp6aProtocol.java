package org.wodichka.passwordgate.security;

import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.CryptoException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Srp6aProtocol implements PasswordAuthProtocol {
    public static final int MAX_INTEGER_BYTES = 384;
    private final SecureRandom random;
    public Srp6aProtocol() { this(new SecureRandom()); }
    public Srp6aProtocol(SecureRandom random) { this.random = random; }

    @Override public Registration createRegistration(byte[] identity, char[] password) {
        byte[] salt = new byte[32]; random.nextBytes(salt);
        return createRegistration(identity, password, salt);
    }

    @Override public Registration createRegistration(byte[] identity, char[] password, byte[] salt) {
        if (salt == null || salt.length != 32) throw new IllegalArgumentException("salt must be 32 bytes");
        salt = salt.clone();
        byte[] p = SecretBytes.utf8(password);
        try {
            SRP6VerifierGenerator generator = new SRP6VerifierGenerator();
            generator.init(SRP6StandardGroups.rfc5054_3072, new SHA256Digest());
            return new Registration(salt, generator.generateVerifier(salt, identity, p));
        } finally { Arrays.fill(p, (byte) 0); }
    }

    @Override public ClientExchange startClient(byte[] identity, char[] password, byte[] salt, BigInteger serverPublic) {
        validatePublic(serverPublic);
        byte[] p = SecretBytes.utf8(password);
        try {
            SRP6Client client = new SRP6Client();
            client.init(SRP6StandardGroups.rfc5054_3072, new SHA256Digest(), random);
            BigInteger a = client.generateClientCredentials(salt, identity, p);
            client.calculateSecret(serverPublic);
            byte[] m1 = unsigned(client.calculateClientEvidenceMessage());
            return new Client(client, a, m1);
        } catch (CryptoException e) { throw new IllegalArgumentException("invalid SRP challenge", e); }
        finally { Arrays.fill(p, (byte) 0); }
    }

    @Override public ServerExchange startServer(BigInteger verifier) {
        validateVerifier(verifier);
        SRP6Server server = new SRP6Server();
        server.init(SRP6StandardGroups.rfc5054_3072, verifier, new SHA256Digest(), random);
        return new Server(server, server.generateServerCredentials());
    }

    public static void validatePublic(BigInteger value) {
        if (value == null || value.signum() <= 0 || value.bitLength() > 3072 ||
                value.mod(SRP6StandardGroups.rfc5054_3072.getN()).equals(BigInteger.ZERO))
            throw new IllegalArgumentException("invalid SRP public value");
    }
    public static void validateVerifier(BigInteger value) {
        if (value == null || value.signum() <= 0 || value.compareTo(SRP6StandardGroups.rfc5054_3072.getN()) >= 0)
            throw new IllegalArgumentException("invalid SRP verifier");
    }
    public static byte[] unsigned(BigInteger value) {
        byte[] raw = value.toByteArray();
        return raw.length > 1 && raw[0] == 0 ? Arrays.copyOfRange(raw, 1, raw.length) : raw;
    }

    private static final class Client implements ClientExchange {
        private SRP6Client delegate; private final BigInteger a; private byte[] m1;
        Client(SRP6Client delegate, BigInteger a, byte[] m1) { this.delegate = delegate; this.a = a; this.m1 = m1; }
        public BigInteger publicValue() { return a; }
        public byte[] clientProof() { return m1.clone(); }
        public boolean verifyServerProof(byte[] proof) {
            if (delegate == null || proof == null || proof.length == 0 || proof.length > 64) return false;
            try { return delegate.verifyServerEvidenceMessage(new BigInteger(1, proof)); }
            catch (RuntimeException | CryptoException e) { return false; }
        }
        public void close() { if (m1 != null) Arrays.fill(m1, (byte)0); m1 = null; delegate = null; }
    }

    private static final class Server implements ServerExchange {
        private SRP6Server delegate; private final BigInteger b;
        Server(SRP6Server delegate, BigInteger b) { this.delegate = delegate; this.b = b; }
        public BigInteger publicValue() { return b; }
        public byte[] verifyClient(BigInteger clientPublic, byte[] proof) {
            if (delegate == null || proof == null || proof.length == 0 || proof.length > 64) return null;
            try {
                validatePublic(clientPublic);
                delegate.calculateSecret(clientPublic);
                if (!delegate.verifyClientEvidenceMessage(new BigInteger(1, proof))) return null;
                return unsigned(delegate.calculateServerEvidenceMessage());
            } catch (RuntimeException | CryptoException e) { return null; }
        }
        public void close() { delegate = null; }
    }
}
