package org.wodichka.passwordgate.common;

import net.minecraft.network.Connection;
import org.wodichka.passwordgate.network.AuthPacket;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import java.util.function.Consumer;

public interface AuthenticationSessionManager extends AutoCloseable {
    AuthenticationSession begin(Connection connection, java.util.UUID identity, Consumer<CustomPacketPayload> sender);
    void receive(Connection connection, AuthPacket packet, int transactionId);
    void disconnected(Connection connection);
    @Override void close();
}
