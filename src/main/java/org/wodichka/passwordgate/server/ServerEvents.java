package org.wodichka.passwordgate.server;

import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerConfigurationPacketListenerImpl;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import net.neoforged.neoforge.event.server.ServerAboutToStartEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import net.neoforged.neoforge.network.configuration.ICustomConfigurationTask;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.fml.event.config.ModConfigEvent;
import net.neoforged.fml.config.ModConfig;
import org.wodichka.passwordgate.PasswordGate;
import org.wodichka.passwordgate.commands.PasswordGateCommands;
import org.wodichka.passwordgate.config.ServerConfig;

import java.util.function.Consumer;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

public final class ServerEvents {
    public static final ConfigurationTask.Type AUTH_TASK = new ConfigurationTask.Type(ResourceLocation.fromNamespaceAndPath(PasswordGate.MOD_ID, "authenticate"));
    private ServerEvents() {}

    @SubscribeEvent
    public static void starting(ServerAboutToStartEvent event) {
        try { ServerRuntime.start(event.getServer()); }
        catch(Exception e) { PasswordGate.LOGGER.error("PasswordGate credential storage could not be loaded; refusing server startup",e); throw new IllegalStateException("PasswordGate credential storage is corrupted",e); }
    }

    public static void configurationTasks(RegisterConfigurationTasksEvent event) {
        if (!ServerConfig.snapshot().enabled()) return;
        if (!(event.getListener() instanceof ServerConfigurationPacketListenerImpl listener)) throw new IllegalStateException("Unsupported configuration listener");
        event.register(new ICustomConfigurationTask() {
            @Override public void run(Consumer<CustomPacketPayload> sender) {
                var session=ServerRuntime.begin(listener.getConnection(), listener.gameProfile, sender);
                session.completion().thenAccept(success -> {
                    if(success) listener.getMainThreadEventLoop().execute(() -> {
                        if(listener.getConnection().isConnected()) listener.finishCurrentTask(AUTH_TASK);
                    });
                });
            }
            @Override public ConfigurationTask.Type type() { return AUTH_TASK; }
        });
    }

    public static void configReloading(ModConfigEvent.Reloading event) {
        if(event.getConfig().getType()==ModConfig.Type.SERVER && PasswordGate.MOD_ID.equals(event.getConfig().getModId())) ServerRuntime.reloadFromConfig();
    }

    @SubscribeEvent public static void commands(RegisterCommandsEvent event){PasswordGateCommands.register(event.getDispatcher());}
    @SubscribeEvent public static void stopping(ServerStoppingEvent event){ServerRuntime.stop();}
}
