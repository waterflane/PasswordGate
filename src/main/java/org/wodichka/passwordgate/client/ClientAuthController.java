package org.wodichka.passwordgate.client;

import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import org.wodichka.passwordgate.network.AuthMessageType;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.PasswordAuthProtocol;
import org.wodichka.passwordgate.security.Srp6aProtocol;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ClientAuthController {
    private enum State { IDLE, COMPUTING, WAIT_CHALLENGE, WAIT_SERVER_PROOF }
    private static final ExecutorService CRYPTO = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "PasswordGate client crypto"); t.setDaemon(true); return t;
    });
    private static UUID session;
    private static PasswordAuthProtocol.ClientExchange exchange;
    private static State state = State.IDLE;
    private ClientAuthController() {}

    public static synchronized void receive(AuthPacket packet, IPayloadContext context) {
        if (session != null && !session.equals(packet.sessionId())) { disconnect(context,"disconnect.passwordgate.malformed_packet"); return; }
        if (state == State.COMPUTING) { disconnect(context,"disconnect.passwordgate.malformed_packet"); return; }
        session=packet.sessionId();
        char[] password=ClientSecrets.copy();
        if(password==null){disconnect(context,"disconnect.passwordgate.no_client_password");return;}
        byte[] identity=packet.identity().toString().getBytes(StandardCharsets.UTF_8);
        try {
            if(packet.messageType()==AuthMessageType.REGISTER_REQUEST && (state==State.IDLE || state==State.WAIT_CHALLENGE)) {
                if(password.length<packet.parameter()){disconnect(context,"disconnect.passwordgate.authentication_failed");return;}
                state=State.COMPUTING;
                submit(context, password, () -> {
                    PasswordAuthProtocol.Registration registration=new Srp6aProtocol().createRegistration(identity,password,packet.first());
                    return new AuthPacket(session,packet.identity(),AuthMessageType.REGISTER_SUBMIT,Srp6aProtocol.unsigned(registration.verifier()),null).withSequence(packet.sequence());
                }, State.WAIT_CHALLENGE);
                return;
            }
            if(packet.messageType()==AuthMessageType.CHALLENGE && (state==State.IDLE || state==State.WAIT_CHALLENGE)) {
                state=State.COMPUTING;
                submit(context, password, () -> {
                    PasswordAuthProtocol.ClientExchange next=new Srp6aProtocol().startClient(identity,password,packet.first(),new BigInteger(1,packet.second()));
                    synchronized(ClientAuthController.class){if(exchange!=null)exchange.close();exchange=next;}
                    return new AuthPacket(session,packet.identity(),AuthMessageType.CLIENT_PROOF,Srp6aProtocol.unsigned(next.publicValue()),next.clientProof()).withSequence(packet.sequence());
                }, State.WAIT_SERVER_PROOF);
                return;
            }
            if(packet.messageType()==AuthMessageType.SERVER_PROOF && state==State.WAIT_SERVER_PROOF && exchange!=null && exchange.verifyServerProof(packet.second())) {
                context.reply(new AuthPacket(session,packet.identity(),AuthMessageType.ACK,null,null).withSequence(packet.sequence()));
                reset(); Arrays.fill(password,'\0'); return;
            }
            Arrays.fill(password,'\0'); disconnect(context,"disconnect.passwordgate.authentication_failed");
        } catch(RuntimeException e) { Arrays.fill(password,'\0'); disconnect(context,"disconnect.passwordgate.authentication_failed"); }
    }

    private static void submit(IPayloadContext context, char[] password, java.util.concurrent.Callable<AuthPacket> job, State next) {
        CRYPTO.submit(() -> {
            AuthPacket reply;
            try { reply=job.call(); }
            catch(Exception e) { Arrays.fill(password,'\0'); Minecraft.getInstance().execute(() -> disconnect(context,"disconnect.passwordgate.authentication_failed")); return; }
            Arrays.fill(password,'\0');
            Minecraft.getInstance().execute(() -> { synchronized(ClientAuthController.class){if(state!=State.COMPUTING)return;state=next;} context.reply(reply); });
        });
    }
    private static synchronized void reset(){if(exchange!=null)exchange.close();exchange=null;session=null;state=State.IDLE;}
    public static void disconnectCleanup(){reset();}
    private static void disconnect(IPayloadContext context,String key){reset();context.disconnect(Component.translatable(key));}
}
