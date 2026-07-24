package org.wodichka.passwordgate.network;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class AuthPacketTest {
    @Test void roundTrips(){UUID s=UUID.randomUUID(),i=UUID.randomUUID();var original=new AuthPacket(s,i,AuthMessageType.CHALLENGE,new byte[32],new byte[]{1,2});FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());original.encode(b);var decoded=AuthPacket.decode(b);assertEquals(s,decoded.sessionId());assertEquals(i,decoded.identity());assertArrayEquals(new byte[]{1,2},decoded.second());}
    @Test void rejectsMalformedAndTrailingData(){FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());b.writeVarInt(1);b.writeVarInt(1);b.writeUUID(UUID.randomUUID());b.writeUUID(UUID.randomUUID());b.writeEnum(AuthMessageType.ACK);b.writeVarInt(0);b.writeVarInt(0);b.writeVarInt(0);b.writeByte(9);assertThrows(IllegalArgumentException.class,()->AuthPacket.decode(b));}
    @Test void sequenceIsAuthenticatedByStateMachineEnvelope(){UUID s=UUID.randomUUID(),i=UUID.randomUUID();var p=new AuthPacket(s,i,AuthMessageType.ACK,null,null).withSequence(41);FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());p.encode(b);assertEquals(41,AuthPacket.decode(b).sequence());}
    @Test void rejectsOversizedPacket(){FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());b.writeZero(AuthPacket.MAX_PACKET_BYTES+1);assertThrows(IllegalArgumentException.class,()->AuthPacket.decode(b));}
    @Test void rejectsOversizedFields(){assertThrows(IllegalArgumentException.class,()->new AuthPacket(UUID.randomUUID(),UUID.randomUUID(),AuthMessageType.CLIENT_PROOF,new byte[385],new byte[]{1}));}
    @Test void permitsFullSizeSrpServerPublicValueButNotOversizedProof(){UUID s=UUID.randomUUID(),i=UUID.randomUUID();assertDoesNotThrow(()->new AuthPacket(s,i,AuthMessageType.CHALLENGE,new byte[32],new byte[384]));assertThrows(IllegalArgumentException.class,()->new AuthPacket(s,i,AuthMessageType.SERVER_PROOF,null,new byte[65]));}
}
