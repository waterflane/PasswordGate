package org.wodichka.passwordgate.security;

import java.util.concurrent.TimeUnit;

public record MonotonicDeadline(long deadlineNanos) {
    public static MonotonicDeadline afterSeconds(long nowNanos,int seconds){if(seconds<1)throw new IllegalArgumentException();return new MonotonicDeadline(nowNanos+TimeUnit.SECONDS.toNanos(seconds));}
    public boolean expired(long nowNanos){return nowNanos-deadlineNanos>=0;}
}
