package org.wodichka.passwordgate;

import com.mojang.logging.LogUtils;
import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.fml.loading.FMLEnvironment;
import net.minecraftforge.fml.ModLoadingContext;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.config.ModConfig;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import org.slf4j.Logger;
import org.wodichka.passwordgate.config.ServerConfig;
import org.wodichka.passwordgate.config.ClientConfig;
import org.wodichka.passwordgate.network.AuthNetwork;
import org.wodichka.passwordgate.server.ServerEvents;

@Mod(PasswordGate.MOD_ID)
public final class PasswordGate {
    public static final String MOD_ID = "passwordgate";
    public static final String PROTOCOL_VERSION = "1";
    public static final Logger LOGGER = LogUtils.getLogger();

    public PasswordGate() {
        ModLoadingContext.get().registerConfig(ModConfig.Type.SERVER, ServerConfig.SPEC, "passwordgate-server.toml");
        ModLoadingContext.get().registerConfig(ModConfig.Type.CLIENT, ClientConfig.SPEC, "passwordgate-client.toml");
        AuthNetwork.register();
        MinecraftForge.EVENT_BUS.register(ServerEvents.class);
        if (FMLEnvironment.dist == Dist.CLIENT) loadClientBootstrap();
    }

    private static void loadClientBootstrap() {
        try { Class.forName("org.wodichka.passwordgate.client.ClientBootstrap").getMethod("register").invoke(null); }
        catch (ReflectiveOperationException e) { throw new IllegalStateException("Could not initialize PasswordGate client", e); }
    }
}
