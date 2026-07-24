package org.wodichka.passwordgate.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.client.event.ScreenEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import org.wodichka.passwordgate.storage.AesGcmClientCredentialStore;

public final class ClientBootstrap {
    private static boolean accepted, credentialChecked, gateRequired;
    private ClientBootstrap(){}
    public static void register(){MinecraftForge.EVENT_BUS.register(ClientBootstrap.class);}
    @SubscribeEvent public static void opening(ScreenEvent.Opening event){if(event.getNewScreen() instanceof TitleScreen&&shouldShowGate(Minecraft.getInstance()))event.setNewScreen(new PasswordGateScreen(()->accepted=true));}
    private static synchronized boolean shouldShowGate(Minecraft minecraft){
        if(!credentialChecked){
            accepted=StoredCredentialLoader.load(new AesGcmClientCredentialStore(minecraft.gameDirectory.toPath().resolve("passwordgate")));
            gateRequired=!accepted;
            credentialChecked=true;
        }
        return gateRequired&&!accepted;
    }
}
