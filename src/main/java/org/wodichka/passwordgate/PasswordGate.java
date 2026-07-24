package org.wodichka.passwordgate;

import com.mojang.logging.LogUtils;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.neoforge.common.NeoForge;
import org.slf4j.Logger;
import org.wodichka.passwordgate.config.ClientConfig;
import org.wodichka.passwordgate.config.ServerConfig;
import org.wodichka.passwordgate.network.AuthNetwork;
import org.wodichka.passwordgate.server.ServerEvents;

@Mod(PasswordGate.MOD_ID)
public final class PasswordGate {
    public static final String MOD_ID = "passwordgate";
    public static final String PROTOCOL_VERSION = "1";
    public static final Logger LOGGER = LogUtils.getLogger();

    public PasswordGate(IEventBus modBus, ModContainer container) {
        container.registerConfig(ModConfig.Type.SERVER, ServerConfig.SPEC, "passwordgate-server.toml");
        container.registerConfig(ModConfig.Type.CLIENT, ClientConfig.SPEC, "passwordgate-client.toml");
        modBus.addListener(AuthNetwork::registerPayloads);
        modBus.addListener(ServerEvents::configurationTasks);
        modBus.addListener(ServerEvents::configReloading);
        NeoForge.EVENT_BUS.register(ServerEvents.class);
    }
}
