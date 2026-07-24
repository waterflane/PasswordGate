package org.wodichka.passwordgate.client;

import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.client.event.ScreenEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public final class ClientBootstrap {
    private static boolean accepted;
    private ClientBootstrap(){}
    public static void register(){MinecraftForge.EVENT_BUS.register(ClientBootstrap.class);}
    @SubscribeEvent public static void opening(ScreenEvent.Opening event){if(!accepted&&event.getNewScreen() instanceof TitleScreen)event.setNewScreen(new PasswordGateScreen(()->accepted=true));}
}
