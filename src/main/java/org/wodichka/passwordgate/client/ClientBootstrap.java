package org.wodichka.passwordgate.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.TitleScreen;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.client.event.ScreenEvent;
import net.neoforged.neoforge.client.event.ClientPlayerNetworkEvent;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import org.wodichka.passwordgate.storage.AesGcmClientCredentialStore;

@EventBusSubscriber(modid = "passwordgate", value = Dist.CLIENT)
public final class ClientBootstrap {
    private static boolean accepted, credentialChecked, gateRequired;
    private ClientBootstrap() {}
    @SubscribeEvent
    public static void opening(ScreenEvent.Opening event) {
        if(event.getNewScreen() instanceof TitleScreen && shouldShowGate(Minecraft.getInstance())) event.setNewScreen(new PasswordGateScreen(() -> accepted=true));
    }
    @SubscribeEvent
    public static void clientTick(ClientTickEvent.Post event) {
        Minecraft minecraft = Minecraft.getInstance();
        boolean showGate = shouldShowGate(minecraft);
        if(showGate && minecraft.screen instanceof TitleScreen) minecraft.setScreen(new PasswordGateScreen(() -> accepted=true));
    }
    private static synchronized boolean shouldShowGate(Minecraft minecraft) {
        if(!credentialChecked){
            accepted=StoredCredentialLoader.load(new AesGcmClientCredentialStore(minecraft.gameDirectory.toPath().resolve("passwordgate")));
            gateRequired=!accepted;
            credentialChecked=true;
        }
        return gateRequired&&!accepted;
    }
    @SubscribeEvent public static void disconnect(ClientPlayerNetworkEvent.LoggingOut event){ClientAuthController.disconnectCleanup();}
}
