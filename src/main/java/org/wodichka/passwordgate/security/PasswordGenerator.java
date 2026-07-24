package org.wodichka.passwordgate.security;

public interface PasswordGenerator {
    char[] generate(int length);
}
