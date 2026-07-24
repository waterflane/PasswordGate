package org.wodichka.passwordgate.client;

import net.minecraft.network.chat.Component;
import net.minecraftforge.network.NetworkEvent;
import org.wodichka.passwordgate.network.AuthMessageType;
import org.wodichka.passwordgate.network.AuthNetwork;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.PasswordAuthProtocol;
import org.wodichka.passwordgate.security.Srp6aProtocol;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

public final class ClientAuthController {
    private static UUID session; private static PasswordAuthProtocol.ClientExchange exchange;
    private ClientAuthController(){}
    public static synchronized void receive(AuthPacket packet,NetworkEvent.Context ctx){
        if(session!=null&&!session.equals(packet.sessionId())){disconnect(ctx,"disconnect.passwordgate.malformed_packet");return;}
        session=packet.sessionId();char[] password=ClientSecrets.copy();
        if(password==null){disconnect(ctx,"disconnect.passwordgate.no_client_password");return;}
        byte[] identity=packet.identity().toString().getBytes(StandardCharsets.UTF_8);
        try{
            if(packet.type()==AuthMessageType.REGISTER_REQUEST){
                if(password.length<packet.parameter()){disconnect(ctx,"disconnect.passwordgate.authentication_failed");return;}
                PasswordAuthProtocol.Registration registration=new Srp6aProtocol().createRegistration(identity,password,packet.first());
                reply(ctx,new AuthPacket(session,packet.identity(),AuthMessageType.REGISTER_SUBMIT,Srp6aProtocol.unsigned(registration.verifier()),null));return;
            }
            if(packet.type()==AuthMessageType.CHALLENGE){
                if(exchange!=null)exchange.close();exchange=new Srp6aProtocol().startClient(identity,password,packet.first(),new BigInteger(1,packet.second()));
                reply(ctx,new AuthPacket(session,packet.identity(),AuthMessageType.CLIENT_PROOF,Srp6aProtocol.unsigned(exchange.publicValue()),exchange.clientProof()));return;
            }
            if(packet.type()==AuthMessageType.SERVER_PROOF&&exchange!=null&&exchange.verifyServerProof(packet.second())){
                reply(ctx,new AuthPacket(session,packet.identity(),AuthMessageType.ACK,null,null));exchange.close();exchange=null;session=null;return;
            }
            disconnect(ctx,"disconnect.passwordgate.authentication_failed");
        }catch(RuntimeException e){disconnect(ctx,"disconnect.passwordgate.authentication_failed");}
        finally{Arrays.fill(password,'\0');}
    }
    private static void reply(NetworkEvent.Context ctx,AuthPacket packet){AuthNetwork.reply(packet,ctx);}
    private static void disconnect(NetworkEvent.Context ctx,String key){if(exchange!=null)exchange.close();exchange=null;session=null;ctx.getNetworkManager().disconnect(Component.translatable(key));}
}
