package org.wodichka.passwordgate.server;

import net.minecraftforge.event.RegisterCommandsEvent;
import net.minecraftforge.event.entity.player.PlayerNegotiationEvent;
import net.minecraftforge.event.server.ServerAboutToStartEvent;
import net.minecraftforge.event.server.ServerStoppingEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import org.wodichka.passwordgate.PasswordGate;
import org.wodichka.passwordgate.commands.PasswordGateCommands;
import org.wodichka.passwordgate.config.ServerConfig;

public final class ServerEvents {
    private ServerEvents(){}
    @SubscribeEvent public static void starting(ServerAboutToStartEvent event){try{ServerRuntime.start(event.getServer());}catch(Exception e){PasswordGate.LOGGER.error("PasswordGate credential storage could not be loaded; refusing server startup",e);throw new IllegalStateException("PasswordGate credential storage is corrupted",e);}}
    @SubscribeEvent public static void negotiation(PlayerNegotiationEvent event){if(ServerConfig.snapshot().enabled()){var session=ServerRuntime.begin(event.getConnection(),event.getProfile());event.enqueueWork(session.completion());}}
    @SubscribeEvent public static void commands(RegisterCommandsEvent event){PasswordGateCommands.register(event.getDispatcher());}
    @SubscribeEvent public static void stopping(ServerStoppingEvent event){ServerRuntime.stop();}
}
