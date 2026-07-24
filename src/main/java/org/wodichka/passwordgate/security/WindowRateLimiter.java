package org.wodichka.passwordgate.security;

import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class WindowRateLimiter implements AuthenticationRateLimiter {
    private final int maxUuidAttempts, maxIpAttempts;
    private final long windowNanos, lockoutNanos;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    public WindowRateLimiter(int maxAttempts, int windowSeconds, int lockoutSeconds) {
        this.maxUuidAttempts = maxAttempts;
        this.maxIpAttempts = Math.max(10, maxAttempts * 4); // shared-IP friendly
        this.windowNanos = windowSeconds * 1_000_000_000L;
        this.lockoutNanos = lockoutSeconds * 1_000_000_000L;
    }
    @Override public boolean isLocked(UUID uuid, InetAddress ip, long now) {
        return locked(entries.get("u:" + uuid), now) || (ip != null && locked(entries.get("i:" + ip.getHostAddress()), now));
    }
    @Override public void recordFailure(UUID uuid, InetAddress ip, long now) {
        fail("u:" + uuid, maxUuidAttempts, now);
        if (ip != null) fail("i:" + ip.getHostAddress(), maxIpAttempts, now);
    }
    @Override public void recordSuccess(UUID uuid, InetAddress ip) { entries.remove("u:" + uuid); }
    private void fail(String key, int limit, long now) {
        entries.compute(key, (k,e) -> {
            if (e == null) e = new Entry();
            synchronized (e) {
                prune(e, now); e.failures.addLast(now);
                if (e.failures.size() >= limit) e.lockedUntil = Math.max(e.lockedUntil, now + lockoutNanos);
            }
            return e;
        });
    }
    private boolean locked(Entry e, long now) {
        if (e == null) return false;
        synchronized (e) { prune(e, now); return now < e.lockedUntil; }
    }
    private void prune(Entry e, long now) { while (!e.failures.isEmpty() && now - e.failures.peekFirst() > windowNanos) e.failures.removeFirst(); }
    @Override public void cleanup(long now) { entries.entrySet().removeIf(x -> { Entry e=x.getValue(); synchronized(e){ prune(e,now); return e.failures.isEmpty() && now >= e.lockedUntil; }}); }
    private static final class Entry { final Deque<Long> failures = new ArrayDeque<>(); long lockedUntil; }
}
