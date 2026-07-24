package org.wodichka.passwordgate.storage;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.UUID;

public record CredentialRecord(int formatVersion, int schemeVersion, UUID uuid, byte[] salt,
                               BigInteger verifier, long registeredAt, long lastAuthenticatedAt,
                               int failedAttempts) {
    public static final int FORMAT_VERSION = 1;
    public static final int SCHEME_SRP6A_SHA256_3072 = 1;
    public CredentialRecord {
        if (formatVersion != FORMAT_VERSION || schemeVersion != SCHEME_SRP6A_SHA256_3072) throw new IllegalArgumentException("unsupported credential version");
        if (uuid == null || salt == null || salt.length != 32) throw new IllegalArgumentException("invalid credential record");
        salt = salt.clone();
        org.wodichka.passwordgate.security.Srp6aProtocol.validateVerifier(verifier);
    }
    @Override public byte[] salt() { return salt.clone(); }
    public CredentialRecord authenticated(long at) { return new CredentialRecord(formatVersion, schemeVersion, uuid, salt, verifier, registeredAt, at, 0); }
    public CredentialRecord failed() { return new CredentialRecord(formatVersion, schemeVersion, uuid, salt, verifier, registeredAt, lastAuthenticatedAt, failedAttempts + 1); }
}
