package org.wodichka.passwordgate.storage;

import java.io.IOException;

interface LocalKeyProtector {
    boolean available();
    byte[] protect(byte[] value) throws IOException;
    byte[] unprotect(byte[] value) throws IOException;
}
