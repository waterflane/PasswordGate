package org.wodichka.passwordgate.config;

import net.neoforged.neoforge.common.ModConfigSpec;

public final class ServerConfig {
    private static final ModConfigSpec.Builder B = new ModConfigSpec.Builder();
    public static final ModConfigSpec.BooleanValue ENABLED = B.define("enabled", true);
    public static final ModConfigSpec.IntValue TIMEOUT = B.defineInRange("authenticationTimeoutSeconds", 15, 5, 120);
    public static final ModConfigSpec.BooleanValue FIRST_JOIN = B.define("allowFirstJoinRegistration", true);
    public static final ModConfigSpec.BooleanValue REQUIRE_ONLINE = B.comment("Legacy compatibility option; offline-mode no longer blocks PasswordGate registration.").define("requireOnlineModeForRegistration", false);
    public static final ModConfigSpec.BooleanValue UNSAFE_OFFLINE = B.comment("Legacy compatibility option; offline-mode no longer blocks PasswordGate registration.").define("allowUnsafeOfflineMode", true);
    public static final ModConfigSpec.IntValue MIN_PASSWORD = B.defineInRange("minimumPasswordLength", 12, 8, 256);
    public static final ModConfigSpec.IntValue GENERATED_LENGTH = B.defineInRange("generatedPasswordLength", 24, 21, 256);
    public static final ModConfigSpec.IntValue MAX_FAILURES = B.defineInRange("maxFailedAttempts", 5, 1, 100);
    public static final ModConfigSpec.IntValue FAILURE_WINDOW = B.defineInRange("failedAttemptWindowSeconds", 300, 10, 86400);
    public static final ModConfigSpec.IntValue LOCKOUT = B.defineInRange("temporaryLockoutSeconds", 300, 10, 86400);
    public static final ModConfigSpec SPEC = B.build();

    private ServerConfig() {}

    public static ValidatedConfig snapshot() {
        return ValidatedConfig.validate(new ValidatedConfig(ENABLED.get(), TIMEOUT.get(), FIRST_JOIN.get(),
                REQUIRE_ONLINE.get(), UNSAFE_OFFLINE.get(), MIN_PASSWORD.get(), GENERATED_LENGTH.get(),
                MAX_FAILURES.get(), FAILURE_WINDOW.get(), LOCKOUT.get()));
    }
}
