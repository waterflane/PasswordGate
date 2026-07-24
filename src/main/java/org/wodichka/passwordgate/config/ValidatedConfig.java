package org.wodichka.passwordgate.config;

public record ValidatedConfig(boolean enabled, int authenticationTimeoutSeconds,
                              boolean allowFirstJoinRegistration, boolean requireOnlineModeForRegistration,
                              boolean allowUnsafeOfflineMode, int minimumPasswordLength,
                              int generatedPasswordLength, int maxFailedAttempts,
                              int failedAttemptWindowSeconds, int temporaryLockoutSeconds) {
    public static ValidatedConfig validate(ValidatedConfig c) {
        return new ValidatedConfig(c.enabled, clamp(c.authenticationTimeoutSeconds, 5, 120),
                c.allowFirstJoinRegistration, c.requireOnlineModeForRegistration, c.allowUnsafeOfflineMode,
                clamp(c.minimumPasswordLength, 8, 256), clamp(c.generatedPasswordLength, 20, 256),
                clamp(c.maxFailedAttempts, 1, 100), clamp(c.failedAttemptWindowSeconds, 10, 86400),
                clamp(c.temporaryLockoutSeconds, 10, 86400));
    }

    private static int clamp(int value, int min, int max) { return Math.max(min, Math.min(max, value)); }
}
