package org.wodichka.passwordgate.security;

import org.bouncycastle.crypto.Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class JcaSha256Digest implements Digest {
    private final MessageDigest delegate;

    JcaSha256Digest() {
        try {
            delegate = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Java runtime does not provide SHA-256", e);
        }
    }

    @Override public String getAlgorithmName() { return "SHA-256"; }
    @Override public int getDigestSize() { return 32; }
    @Override public void update(byte in) { delegate.update(in); }
    @Override public void update(byte[] in, int inOff, int len) { delegate.update(in, inOff, len); }
    @Override public int doFinal(byte[] out, int outOff) {
        byte[] digest = delegate.digest();
        System.arraycopy(digest, 0, out, outOff, digest.length);
        return digest.length;
    }
    @Override public void reset() { delegate.reset(); }
}
