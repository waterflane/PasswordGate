package org.wodichka.passwordgate.network;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import org.wodichka.passwordgate.PasswordGate;
import org.wodichka.passwordgate.security.Srp6aProtocol;

import java.util.UUID;

public final class AuthPacket implements CustomPacketPayload {
    public static final int VERSION = 1, MAX_PACKET_BYTES = 1536, MAX_PROOF_BYTES = 64;
    public static final Type<AuthPacket> TYPE = new Type<>(ResourceLocation.fromNamespaceAndPath(PasswordGate.MOD_ID, "authentication"));
    public static final StreamCodec<FriendlyByteBuf, AuthPacket> STREAM_CODEC = StreamCodec.ofMember(AuthPacket::encode, AuthPacket::decode);
    private final int version, sequence;
    private final UUID sessionId, identity;
    private final AuthMessageType messageType;
    private final int parameter;
    private final byte[] first, second;

    public AuthPacket(UUID sessionId, UUID identity, AuthMessageType type, byte[] first, byte[] second) {
        this(VERSION, 0, sessionId, identity, type, 0, first, second);
    }
    public AuthPacket(UUID sessionId, UUID identity, AuthMessageType type, int parameter, byte[] first, byte[] second) {
        this(VERSION, 0, sessionId, identity, type, parameter, first, second);
    }
    public AuthPacket withSequence(int sequence) {
        return new AuthPacket(version, sequence, sessionId, identity, messageType, parameter, first, second);
    }
    private AuthPacket(int version, int sequence, UUID sessionId, UUID identity, AuthMessageType type, int parameter, byte[] first, byte[] second) {
        this.version=version; this.sequence=sequence; this.sessionId=sessionId; this.identity=identity; this.messageType=type; this.parameter=parameter;
        this.first=first == null ? new byte[0] : first.clone(); this.second=second == null ? new byte[0] : second.clone();
        validate();
    }
    public void encode(FriendlyByteBuf b) { b.writeVarInt(version); b.writeVarInt(sequence); b.writeUUID(sessionId); b.writeUUID(identity); b.writeEnum(messageType); b.writeVarInt(parameter); write(b,first); write(b,second); }
    public static AuthPacket decode(FriendlyByteBuf b) {
        if (b.readableBytes() > MAX_PACKET_BYTES) throw new IllegalArgumentException("oversized PasswordGate packet");
        AuthPacket p = new AuthPacket(b.readVarInt(), b.readVarInt(), b.readUUID(), b.readUUID(), b.readEnum(AuthMessageType.class), b.readVarInt(), read(b, Srp6aProtocol.MAX_INTEGER_BYTES), read(b, Srp6aProtocol.MAX_INTEGER_BYTES));
        if (b.isReadable()) throw new IllegalArgumentException("trailing PasswordGate data");
        return p;
    }
    private void validate() {
        if (version != VERSION || sequence < 0 || sessionId == null || identity == null || messageType == null || first.length > Srp6aProtocol.MAX_INTEGER_BYTES || second.length > Srp6aProtocol.MAX_INTEGER_BYTES)
            throw new IllegalArgumentException("invalid PasswordGate packet");
        switch (messageType) {
            case REGISTER_REQUEST -> require(parameter>=8&&parameter<=256&&first.length == 32 && second.length == 0);
            case REGISTER_SUBMIT -> require(parameter==0&&first.length >= 1 && second.length == 0);
            case CHALLENGE -> require(parameter==0&&first.length == 32 && second.length >= 1);
            case CLIENT_PROOF -> require(parameter==0&&first.length >= 1 && second.length >= 1 && second.length <= MAX_PROOF_BYTES);
            case SERVER_PROOF -> require(parameter==0&&first.length == 0 && second.length >= 1 && second.length <= MAX_PROOF_BYTES);
            case ACK -> require(parameter==0&&first.length == 0 && second.length == 0);
        }
    }
    private static void require(boolean ok) { if (!ok) throw new IllegalArgumentException("malformed PasswordGate packet"); }
    private static void write(FriendlyByteBuf b, byte[] value) { b.writeVarInt(value.length); b.writeBytes(value); }
    private static byte[] read(FriendlyByteBuf b, int max) { int n=b.readVarInt(); if(n<0||n>max||n>b.readableBytes()) throw new IllegalArgumentException("invalid field size"); byte[] v=new byte[n]; b.readBytes(v); return v; }
    public UUID sessionId(){return sessionId;} public UUID identity(){return identity;} public AuthMessageType messageType(){return messageType;}
    public AuthMessageType typeValue(){return messageType;} public int sequence(){return sequence;} public int parameter(){return parameter;}
    public byte[] first(){return first.clone();} public byte[] second(){return second.clone();}
    @Override public Type<? extends CustomPacketPayload> type(){return TYPE;}
}
