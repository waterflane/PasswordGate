package org.wodichka.passwordgate.client;

import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;
import org.wodichka.passwordgate.config.ClientConfig;
import org.wodichka.passwordgate.security.SecurePasswordGenerator;
import org.wodichka.passwordgate.storage.AesGcmClientCredentialStore;
import org.wodichka.passwordgate.storage.ClientCredentialStore;

import java.io.IOException;
import java.util.Arrays;

final class PasswordGateScreen extends Screen {
    private final Runnable accepted; private ClientCredentialStore store; private EditBox password;
    private boolean visible,hasStored,confirmReplace,confirmReset,generated; private Component status=Component.empty();
    PasswordGateScreen(Runnable accepted){super(Component.translatable("screen.passwordgate.title"));this.accepted=accepted;}
    @Override protected void init(){
        store=new AesGcmClientCredentialStore(minecraft.gameDirectory.toPath().resolve("passwordgate"));
        try{var loaded=store.load();hasStored=loaded.isPresent();loaded.ifPresent(chars->Arrays.fill(chars,'\0'));}
        catch(IOException e){status=Component.translatable("screen.passwordgate.corrupted").withStyle(ChatFormatting.RED);}
        int x=width/2-120,y=height/2-52;password=new EditBox(font,x,y,240,20,Component.translatable("screen.passwordgate.password"));password.setMaxLength(256);updateFormatter();addRenderableWidget(password);
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.show"),b->{visible=!visible;updateFormatter();b.setMessage(Component.translatable(visible?"screen.passwordgate.hide":"screen.passwordgate.show"));}).bounds(x+244,y,70,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.confirm"),b->confirm()).bounds(x,y+28,116,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.generate"),b->generate()).bounds(x+124,y+28,116,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.copy"),b->copy()).bounds(x,y+54,116,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.reset_local"),b->reset()).bounds(x+124,y+54,116,20).build());
        setInitialFocus(password);
        if(!store.secureStorageAvailable())status=Component.translatable("screen.passwordgate.no_secure_store").withStyle(ChatFormatting.YELLOW);
    }
    private void updateFormatter(){if(password!=null)password.setFormatter((text,pos)->FormattedCharSequence.forward(visible?text:"•".repeat(text.length()),Style.EMPTY));}
    private void generate(){char[] chars=new SecurePasswordGenerator().generate(ClientConfig.GENERATED_LENGTH.get());password.setValue(new String(chars));Arrays.fill(chars,'\0');generated=true;confirmReplace=false;status=Component.translatable("screen.passwordgate.save_warning").withStyle(ChatFormatting.YELLOW);}
    private void copy(){if(password.getValue().isEmpty()){status=Component.translatable("screen.passwordgate.empty").withStyle(ChatFormatting.RED);return;}minecraft.keyboardHandler.setClipboard(password.getValue());status=Component.translatable("screen.passwordgate.copied").withStyle(ChatFormatting.GREEN);}
    private void confirm(){
        if(password.getValue().isEmpty()&&hasStored){try{char[] chars=store.load().orElseThrow();ClientSecrets.set(chars);Arrays.fill(chars,'\0');finish();}catch(Exception e){status=Component.translatable("screen.passwordgate.corrupted").withStyle(ChatFormatting.RED);}return;}
        if(password.getValue().length()<12){status=Component.translatable("screen.passwordgate.too_short",12).withStyle(ChatFormatting.RED);return;}
        if(hasStored&&!confirmReplace){confirmReplace=true;status=Component.translatable("screen.passwordgate.confirm_replace").withStyle(ChatFormatting.YELLOW);return;}
        char[] chars=password.getValue().toCharArray();try{if(store.secureStorageAvailable()){store.save(chars);hasStored=true;}ClientSecrets.set(chars);finish();}catch(IOException e){ClientSecrets.set(chars);status=Component.translatable("screen.passwordgate.no_secure_store").withStyle(ChatFormatting.YELLOW);finish();}finally{Arrays.fill(chars,'\0');}
    }
    private void reset(){if(!confirmReset){confirmReset=true;status=Component.translatable("screen.passwordgate.confirm_reset").withStyle(ChatFormatting.YELLOW);return;}try{store.clear();hasStored=false;ClientSecrets.clear();password.setValue("");status=Component.translatable("screen.passwordgate.reset_done").withStyle(ChatFormatting.GREEN);}catch(IOException e){status=Component.translatable("screen.passwordgate.corrupted").withStyle(ChatFormatting.RED);}confirmReset=false;}
    private void finish(){accepted.run();password.setValue("");minecraft.setScreen(new TitleScreen());}
    @Override public void render(GuiGraphics g,int mouseX,int mouseY,float partial){renderBackground(g);g.drawCenteredString(font,title,width/2,height/2-92,0xFFFFFF);g.drawCenteredString(font,Component.translatable(hasStored?"screen.passwordgate.saved_exists":"screen.passwordgate.enter"),width/2,height/2-72,0xB0B0B0);g.drawCenteredString(font,status,width/2,height/2+40,0xFFFFFF);super.render(g,mouseX,mouseY,partial);}
    @Override public boolean shouldCloseOnEsc(){return false;}
}
