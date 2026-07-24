package org.wodichka.passwordgate.common;

import net.minecraft.network.Connection;
import org.wodichka.passwordgate.network.AuthPacket;

public interface AuthenticationSessionManager extends AutoCloseable {
    AuthenticationSession begin(Connection connection, java.util.UUID identity);
    void receive(Connection connection, AuthPacket packet, int transactionId);
    void disconnected(Connection connection);
    @Override void close();
}
