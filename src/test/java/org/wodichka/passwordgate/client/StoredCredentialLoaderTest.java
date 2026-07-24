package org.wodichka.passwordgate.client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.wodichka.passwordgate.storage.ClientCredentialStore;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class StoredCredentialLoaderTest {
    @AfterEach void clearSecrets() { ClientSecrets.clear(); }

    @Test void loadsStoredPasswordAndWipesTemporaryArray() {
        char[] stored = "stored-test-password".toCharArray();
        assertTrue(StoredCredentialLoader.load(storeReturning(Optional.of(stored))));
        assertTrue(ClientSecrets.present());
        assertArrayEquals(new char[stored.length], stored);
        char[] loaded = ClientSecrets.copy();
        assertNotNull(loaded);
        assertEquals("stored-test-password", new String(loaded));
        Arrays.fill(loaded, '\0');
    }

    @Test void requiresGateWhenPasswordIsMissing() {
        assertFalse(StoredCredentialLoader.load(storeReturning(Optional.empty())));
        assertFalse(ClientSecrets.present());
    }

    @Test void requiresGateWhenCredentialCannotBeRead() {
        ClientCredentialStore store = new StubStore() {
            @Override public Optional<char[]> load() throws IOException { throw new IOException("test failure"); }
        };
        assertFalse(StoredCredentialLoader.load(store));
        assertFalse(ClientSecrets.present());
    }

    private static ClientCredentialStore storeReturning(Optional<char[]> value) {
        return new StubStore() {
            @Override public Optional<char[]> load() { return value; }
        };
    }

    private abstract static class StubStore implements ClientCredentialStore {
        @Override public boolean secureStorageAvailable() { return true; }
        @Override public Optional<char[]> load() throws IOException { return Optional.empty(); }
        @Override public void save(char[] password) {}
        @Override public void clear() {}
    }
}
