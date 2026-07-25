package org.wodichka.passwordgate.network;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthNetworkWrapperTest {
    @Test void wrapsDynamicLoginPayloadForForgeLoginWrapper() {
        FriendlyByteBuf payload = new FriendlyByteBuf(Unpooled.buffer());
        payload.writeByte(0x5A);
        payload.writeByte(0x7F);
        int originalReaderIndex = payload.readerIndex();

        FriendlyByteBuf wrapped = AuthNetwork.wrapLoginPayload(payload);

        assertEquals(AuthNetwork.ID, wrapped.readResourceLocation());
        assertEquals(2, wrapped.readVarInt());
        assertEquals(0x5A, wrapped.readUnsignedByte());
        assertEquals(0x7F, wrapped.readUnsignedByte());
        assertFalse(wrapped.isReadable());
        assertEquals(originalReaderIndex, payload.readerIndex());
    }
}
