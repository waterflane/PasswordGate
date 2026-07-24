package org.wodichka.passwordgate.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class SecretBytes {
    private SecretBytes() {}

    public static byte[] utf8(char[] chars) {
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(chars));
            byte[] out = new byte[encoded.remaining()];
            encoded.get(out);
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
            return out;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("invalid password characters", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        return java.security.MessageDigest.isEqual(a,b);
    }
}
