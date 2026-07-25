package org.wodichka.passwordgate.network;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;
import org.junit.jupiter.api.Test;
import org.wodichka.passwordgate.security.Srp6aProtocol;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class AuthPacketTest {
    @Test void roundTrips(){UUID s=UUID.randomUUID(),i=UUID.randomUUID();var original=new AuthPacket(s,i,AuthMessageType.CHALLENGE,new byte[32],new byte[]{1,2});FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());original.encode(b);var decoded=AuthPacket.decode(b);assertEquals(s,decoded.sessionId());assertEquals(i,decoded.identity());assertArrayEquals(new byte[]{1,2},decoded.second());}
    @Test void acceptsReal3072BitServerChallenge(){UUID identity=UUID.randomUUID();var protocol=new Srp6aProtocol();var registration=protocol.createRegistration(identity.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),"correct-password-123".toCharArray());try(var server=protocol.startServer(registration.verifier())){byte[] publicValue=Srp6aProtocol.unsigned(server.publicValue());assertTrue(publicValue.length>64);var packet=new AuthPacket(UUID.randomUUID(),identity,AuthMessageType.CHALLENGE,registration.salt(),publicValue);FriendlyByteBuf buffer=new FriendlyByteBuf(Unpooled.buffer());packet.encode(buffer);assertArrayEquals(publicValue,AuthPacket.decode(buffer).second());}}
    @Test void rejectsMalformedAndTrailingData(){FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());b.writeVarInt(1);b.writeUUID(UUID.randomUUID());b.writeUUID(UUID.randomUUID());b.writeEnum(AuthMessageType.ACK);b.writeVarInt(0);b.writeVarInt(0);b.writeVarInt(0);b.writeByte(9);assertThrows(IllegalArgumentException.class,()->AuthPacket.decode(b));}
    @Test void rejectsOversizedPacket(){FriendlyByteBuf b=new FriendlyByteBuf(Unpooled.buffer());b.writeZero(AuthPacket.MAX_PACKET_BYTES+1);assertThrows(IllegalArgumentException.class,()->AuthPacket.decode(b));}
    @Test void rejectsOversizedFields(){assertThrows(IllegalArgumentException.class,()->new AuthPacket(UUID.randomUUID(),UUID.randomUUID(),AuthMessageType.CLIENT_PROOF,new byte[385],new byte[]{1}));}
    @Test void stillRejectsOversizedProof(){assertThrows(IllegalArgumentException.class,()->new AuthPacket(UUID.randomUUID(),UUID.randomUUID(),AuthMessageType.SERVER_PROOF,null,new byte[65]));}
}
