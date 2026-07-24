package org.wodichka.passwordgate.security;

import java.security.SecureRandom;

public final class SecurePasswordGenerator implements PasswordGenerator {
    // 80 unambiguous characters: 24 chars provide >151 bits.
    static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@^_".toCharArray();
    private final SecureRandom random;

    public SecurePasswordGenerator() { this(new SecureRandom()); }
    SecurePasswordGenerator(SecureRandom random) { this.random = random; }

    @Override public char[] generate(int length) {
        if (length < 20 || length > 256) throw new IllegalArgumentException("length must be 20..256");
        char[] out = new char[length];
        String[] groups={"ABCDEFGHJKLMNPQRSTUVWXYZ","abcdefghijkmnopqrstuvwxyz","23456789","!#$%&*+-=?@^_"};
        for(int i=0;i<groups.length;i++)out[i]=groups[i].charAt(random.nextInt(groups[i].length()));
        for (int i = groups.length; i < out.length; i++) out[i] = ALPHABET[random.nextInt(ALPHABET.length)];
        for(int i=out.length-1;i>0;i--){int j=random.nextInt(i+1);char t=out[i];out[i]=out[j];out[j]=t;}
        return out;
    }
}
