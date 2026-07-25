package org.wodichka.passwordgate.security;

import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.CryptoException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Srp6aProtocol implements PasswordAuthProtocol {
    public static final int MAX_INTEGER_BYTES = 384;
    // RFC 5054 3072-bit group.
    private static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
            "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
            "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
            "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
            "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
            "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
            "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
            "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
            "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
            "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
            "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
            "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = BigInteger.valueOf(5);
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
            generator.init(N, G, new JcaSha256Digest());
            return new Registration(salt, generator.generateVerifier(salt, identity, p));
        } finally { Arrays.fill(p, (byte) 0); }
    }

    @Override public ClientExchange startClient(byte[] identity, char[] password, byte[] salt, BigInteger serverPublic) {
        validatePublic(serverPublic);
        byte[] p = SecretBytes.utf8(password);
        try {
            SRP6Client client = new SRP6Client();
            client.init(N, G, new JcaSha256Digest(), random);
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
        server.init(N, G, verifier, new JcaSha256Digest(), random);
        return new Server(server, server.generateServerCredentials());
    }

    public static void validatePublic(BigInteger value) {
        if (value == null || value.signum() <= 0 || value.bitLength() > 3072 ||
                value.mod(N).equals(BigInteger.ZERO))
            throw new IllegalArgumentException("invalid SRP public value");
    }
    public static void validateVerifier(BigInteger value) {
        if (value == null || value.signum() <= 0 || value.compareTo(N) >= 0)
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
