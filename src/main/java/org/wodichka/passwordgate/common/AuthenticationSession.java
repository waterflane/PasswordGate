package org.wodichka.passwordgate.common;

import org.wodichka.passwordgate.network.AuthPacket;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface AuthenticationSession extends AutoCloseable {
    UUID id();
    CompletableFuture<Void> completion();
    void receive(AuthPacket packet, int transactionId);
    void timeout();
    @Override void close();
}
