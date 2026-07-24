package org.wodichka.passwordgate.network;

import io.netty.buffer.Unpooled;
import net.minecraft.network.Connection;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;
import net.minecraftforge.fml.LogicalSide;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.simple.SimpleChannel;
import org.apache.commons.lang3.tuple.Pair;
import org.wodichka.passwordgate.PasswordGate;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public final class AuthNetwork {
    public static final ResourceLocation ID=new ResourceLocation(PasswordGate.MOD_ID,"login");
    private static final AtomicInteger TRANSACTION=new AtomicInteger(0x40000000);
    private static SimpleChannel channel;
    private AuthNetwork(){}
    public static void register(){
        channel=NetworkRegistry.ChannelBuilder.named(ID).networkProtocolVersion(()->PasswordGate.PROTOCOL_VERSION)
                .clientAcceptedVersions(PasswordGate.PROTOCOL_VERSION::equals).serverAcceptedVersions(PasswordGate.PROTOCOL_VERSION::equals).simpleChannel();
        channel.messageBuilder(AuthPacket.class,0).encoder(AuthPacket::encode).decoder(AuthPacket::decode)
                .loginIndex(AuthPacket::getAsInt,AuthPacket::setLoginIndex).consumerNetworkThread(AuthNetwork::handle).add();
    }
    private static void handle(AuthPacket packet,Supplier<NetworkEvent.Context> supplier){
        NetworkEvent.Context ctx=supplier.get();ctx.setPacketHandled(true);
        try{
            if(ctx.getDirection().getReceptionSide()== LogicalSide.SERVER) org.wodichka.passwordgate.server.ServerRuntime.receive(ctx.getNetworkManager(),packet,packet.getAsInt());
            else org.wodichka.passwordgate.client.ClientAuthController.receive(packet,ctx);
        }catch(RuntimeException e){ctx.getNetworkManager().disconnect(net.minecraft.network.chat.Component.translatable("disconnect.passwordgate.malformed_packet"));}
    }
    public static int nextTransaction(){return TRANSACTION.updateAndGet(v->v==Integer.MAX_VALUE?0x40000000:v+1);}
    public static void sendLogin(Connection connection,AuthPacket packet,int transaction){
        FriendlyByteBuf data=new FriendlyByteBuf(Unpooled.buffer());channel.encodeMessage(packet,data);
        connection.send(NetworkDirection.LOGIN_TO_CLIENT.buildPacket(Pair.of(data,transaction),ID).getThis());
    }
    public static void reply(AuthPacket packet,NetworkEvent.Context ctx){channel.reply(packet,ctx);}
}
