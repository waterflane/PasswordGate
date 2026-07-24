package org.wodichka.passwordgate.security;

import java.net.InetAddress;
import java.time.Duration;
import java.util.UUID;

public interface AuthenticationRateLimiter {
    boolean isLocked(UUID uuid, InetAddress address, long nowNanos);
    void recordFailure(UUID uuid, InetAddress address, long nowNanos);
    void recordSuccess(UUID uuid, InetAddress address);
    void cleanup(long nowNanos);
}
