package org.wodichka.passwordgate.storage;

import java.io.IOException;
import java.util.Optional;

public interface ClientCredentialStore {
    boolean secureStorageAvailable();
    Optional<char[]> load() throws IOException;
    void save(char[] password) throws IOException;
    void clear() throws IOException;
}
