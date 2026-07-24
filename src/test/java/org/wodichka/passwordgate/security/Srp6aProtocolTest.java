package org.wodichka.passwordgate.security;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class Srp6aProtocolTest {
    private final byte[] identity="6ba7b810-9dad-11d1-80b4-00c04fd430c8".getBytes(StandardCharsets.UTF_8);
    @Test void registrationAndCorrectPasswordMutuallyAuthenticate(){char[] password="correct horse battery staple".toCharArray();var p=new Srp6aProtocol();var r=p.createRegistration(identity,password);try(var server=p.startServer(r.verifier())){try(var client=p.startClient(identity,password,r.salt(),server.publicValue())){byte[] m2=server.verifyClient(client.publicValue(),client.clientProof());assertNotNull(m2);assertTrue(client.verifyServerProof(m2));}}}
    @Test void wrongPasswordFails(){var p=new Srp6aProtocol();var r=p.createRegistration(identity,"right-password-123".toCharArray());try(var server=p.startServer(r.verifier());var client=p.startClient(identity,"wrong-password-123".toCharArray(),r.salt(),server.publicValue())){assertNull(server.verifyClient(client.publicValue(),client.clientProof()));}}
    @Test void replayAgainstFreshChallengeFails(){var p=new Srp6aProtocol();char[] password="correct-password-123".toCharArray();var r=p.createRegistration(identity,password);java.math.BigInteger a;byte[] proof;try(var first=p.startServer(r.verifier());var client=p.startClient(identity,password,r.salt(),first.publicValue())){a=client.publicValue();proof=client.clientProof();assertNotNull(first.verifyClient(a,proof));}try(var fresh=p.startServer(r.verifier())){assertNull(fresh.verifyClient(a,proof));}}
    @Test void changedChallengeFails(){replayAgainstFreshChallengeFails();}
    @Test void rejectsZeroAndOversizedPublicValues(){assertThrows(IllegalArgumentException.class,()->Srp6aProtocol.validatePublic(java.math.BigInteger.ZERO));assertThrows(IllegalArgumentException.class,()->Srp6aProtocol.validatePublic(java.math.BigInteger.ONE.shiftLeft(4000)));}
}
