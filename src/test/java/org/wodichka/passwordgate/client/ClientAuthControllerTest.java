package org.wodichka.passwordgate.client;

import org.junit.jupiter.api.Test;
import org.wodichka.passwordgate.network.AuthMessageType;
import org.wodichka.passwordgate.network.AuthPacket;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ClientAuthControllerTest {
    @Test void onlyFirstRegistrationOrChallengePacketCanReplaceAStaleSession() {
        UUID session=UUID.randomUUID(), identity=UUID.randomUUID();
        assertTrue(ClientAuthController.isInitial(new AuthPacket(session,identity,AuthMessageType.REGISTER_REQUEST,12,new byte[32],null).withSequence(1)));
        assertTrue(ClientAuthController.isInitial(new AuthPacket(session,identity,AuthMessageType.CHALLENGE,new byte[32],new byte[]{1}).withSequence(1)));
        assertFalse(ClientAuthController.isInitial(new AuthPacket(session,identity,AuthMessageType.CHALLENGE,new byte[32],new byte[]{1}).withSequence(2)));
        assertFalse(ClientAuthController.isInitial(new AuthPacket(session,identity,AuthMessageType.SERVER_PROOF,null,new byte[]{1}).withSequence(1)));
    }
}
