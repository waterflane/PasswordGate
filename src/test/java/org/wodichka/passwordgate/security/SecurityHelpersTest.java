package org.wodichka.passwordgate.security;

import org.junit.jupiter.api.Test;
import java.net.InetAddress;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class SecurityHelpersTest {
    @Test void constantTimeHelperComparesContent(){assertTrue(SecretBytes.constantTimeEquals(new byte[]{1,2},new byte[]{1,2}));assertFalse(SecretBytes.constantTimeEquals(new byte[]{1,2},new byte[]{1,3}));assertFalse(SecretBytes.constantTimeEquals(new byte[]{1},new byte[]{1,0}));}
    @Test void monotonicDeadlineExpires(){var d=MonotonicDeadline.afterSeconds(1_000,5);assertFalse(d.expired(5_000_000_999L));assertTrue(d.expired(5_000_001_000L));}
    @Test void rateLimitsUuidAndCleansUp()throws Exception{var l=new WindowRateLimiter(2,10,20);UUID id=UUID.randomUUID();InetAddress ip=InetAddress.getByName("127.0.0.1");long now=1_000;assertFalse(l.isLocked(id,ip,now));l.recordFailure(id,ip,now);l.recordFailure(id,ip,now+1);assertTrue(l.isLocked(id,null,now+2));assertFalse(l.isLocked(UUID.randomUUID(),ip,now+2));l.recordSuccess(id,ip);assertFalse(l.isLocked(id,null,now+3));l.cleanup(now+40_000_000_000L);}
}
