package org.wodichka.passwordgate.storage;

import java.io.IOException;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface ServerCredentialRepository extends AutoCloseable {
    void load() throws IOException;
    Optional<CredentialRecord> find(UUID uuid);
    CompletableFuture<Void> save(CredentialRecord record);
    CompletableFuture<Boolean> remove(UUID uuid);
    Collection<UUID> registeredUuids();
    @Override void close();
}
