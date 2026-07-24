package org.wodichka.passwordgate.client;

import org.wodichka.passwordgate.storage.ClientCredentialStore;

import java.io.IOException;
import java.util.Arrays;

final class StoredCredentialLoader {
    private StoredCredentialLoader() {}

    static boolean load(ClientCredentialStore store) {
        char[] stored = null;
        try {
            stored = store.load().orElse(null);
            if (stored == null || stored.length == 0) return false;
            ClientSecrets.set(stored);
            return true;
        } catch (IOException | RuntimeException ignored) {
            return false;
        } finally {
            if (stored != null) Arrays.fill(stored, '\0');
        }
    }
}
