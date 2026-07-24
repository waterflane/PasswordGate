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
import org.lwjgl.glfw.GLFW;

final class PasswordGateScreen extends Screen {
    private final Runnable accepted; private ClientCredentialStore store; private EditBox password;
    private boolean visible,hasStored,confirmReplace,confirmReset,generated; private Component status=Component.empty();
    PasswordGateScreen(Runnable accepted){super(Component.translatable("screen.passwordgate.title"));this.accepted=accepted;}
    @Override protected void init(){
        store=new AesGcmClientCredentialStore(minecraft.gameDirectory.toPath().resolve("passwordgate"));
        try{var loaded=store.load();hasStored=loaded.isPresent();loaded.ifPresent(chars->Arrays.fill(chars,'\0'));}
        catch(IOException e){status=Component.translatable("screen.passwordgate.corrupted").withStyle(ChatFormatting.RED);}
        int fieldWidth=Math.min(240,Math.max(140,width-90)),x=(width-fieldWidth-74)/2,y=height/2-52,buttonWidth=(fieldWidth-8)/2;password=new EditBox(font,x,y,fieldWidth,20,Component.translatable("screen.passwordgate.password"));password.setMaxLength(256);updateFormatter();addRenderableWidget(password);
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.show"),b->{visible=!visible;updateFormatter();b.setMessage(Component.translatable(visible?"screen.passwordgate.hide":"screen.passwordgate.show"));}).bounds(x+fieldWidth+4,y,70,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.confirm"),b->confirm()).bounds(x,y+28,buttonWidth,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.generate"),b->generate()).bounds(x+buttonWidth+8,y+28,buttonWidth,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.copy"),b->copy()).bounds(x,y+54,buttonWidth,20).build());
        addRenderableWidget(Button.builder(Component.translatable("screen.passwordgate.reset_local"),b->reset()).bounds(x+buttonWidth+8,y+54,buttonWidth,20).build());
        setInitialFocus(password);
        if(!store.secureStorageAvailable())status=Component.translatable("screen.passwordgate.no_secure_store").withStyle(ChatFormatting.YELLOW);
    }
    private void updateFormatter(){if(password!=null)password.setFormatter((text,pos)->FormattedCharSequence.forward(visible?text:"\u2022".repeat(text.length()),Style.EMPTY));}
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
    @Override public boolean keyPressed(int keyCode,int scanCode,int modifiers){if(keyCode==GLFW.GLFW_KEY_ENTER||keyCode==GLFW.GLFW_KEY_KP_ENTER){confirm();return true;}return super.keyPressed(keyCode,scanCode,modifiers);}
    @Override
    protected void renderBlurredBackground(float partialTick) {
        // PasswordGate is the first screen shown; keep its panorama and text sharp.
    }
    @Override public void render(GuiGraphics g,int mouseX,int mouseY,float partial){renderBackground(g,mouseX,mouseY,partial);drawCenteredWithoutShadow(g,title,width/2,height/2-92,0xFFFFFF);drawCenteredWrappedWithoutShadow(g,Component.translatable(hasStored?"screen.passwordgate.saved_exists":"screen.passwordgate.enter"),width/2,height/2-72,Math.max(140,width-32),0xB0B0B0);drawCenteredWrappedWithoutShadow(g,status,width/2,height/2+40,Math.max(140,width-32),0xFFFFFF);super.render(g,mouseX,mouseY,partial);}
    private void drawCenteredWithoutShadow(GuiGraphics graphics,Component text,int centerX,int y,int color){graphics.drawString(font,text,centerX-font.width(text)/2,y,color,false);}
    private void drawCenteredWrappedWithoutShadow(GuiGraphics graphics,Component text,int centerX,int y,int maxWidth,int color){var lines=font.split(text,maxWidth);for(int i=0;i<lines.size();i++){FormattedCharSequence line=lines.get(i);graphics.drawString(font,line,centerX-font.width(line)/2,y+i*font.lineHeight,color,false);}}
    @Override public boolean shouldCloseOnEsc(){return false;}
}
