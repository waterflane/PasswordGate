package org.wodichka.passwordgate.network;

import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.handling.DirectionalPayloadHandler;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import org.wodichka.passwordgate.PasswordGate;
import org.wodichka.passwordgate.server.ServerRuntime;

public final class AuthNetwork {
    private AuthNetwork() {}

    public static void registerPayloads(RegisterPayloadHandlersEvent event) {
        event.registrar(PasswordGate.PROTOCOL_VERSION).configurationBidirectional(
                AuthPacket.TYPE, AuthPacket.STREAM_CODEC,
                new DirectionalPayloadHandler<>(AuthNetwork::handleClient, AuthNetwork::handleServer));
    }

    private static void handleServer(AuthPacket packet, IPayloadContext context) {
        try {
            ServerRuntime.receive(context.connection(), packet);
        } catch (RuntimeException e) {
            context.disconnect(net.minecraft.network.chat.Component.translatable("disconnect.passwordgate.malformed_packet"));
        }
    }

    private static void handleClient(AuthPacket packet, IPayloadContext context) {
        ClientHandlerBridge.receive(packet, context);
    }

    /** Keeps every net.minecraft.client reference outside classes loaded by a dedicated server. */
    private static final class ClientHandlerBridge {
        private static void receive(AuthPacket packet, IPayloadContext context) {
            try {
                Class<?> handler = Class.forName("org.wodichka.passwordgate.client.ClientAuthController");
                handler.getMethod("receive", AuthPacket.class, IPayloadContext.class).invoke(null, packet, context);
            } catch (ReflectiveOperationException e) {
                context.disconnect(net.minecraft.network.chat.Component.translatable("disconnect.passwordgate.authentication_failed"));
            }
        }
    }
}
