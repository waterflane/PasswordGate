package org.wodichka.passwordgate.config;

import net.minecraftforge.common.ForgeConfigSpec;

public final class ServerConfig {
    private static final ForgeConfigSpec.Builder B = new ForgeConfigSpec.Builder();
    public static final ForgeConfigSpec.BooleanValue ENABLED = B.define("enabled", true);
    public static final ForgeConfigSpec.IntValue TIMEOUT = B.defineInRange("authenticationTimeoutSeconds", 15, 5, 120);
    public static final ForgeConfigSpec.BooleanValue FIRST_JOIN = B.define("allowFirstJoinRegistration", true);
    public static final ForgeConfigSpec.BooleanValue REQUIRE_ONLINE = B.define("requireOnlineModeForRegistration", true);
    public static final ForgeConfigSpec.BooleanValue UNSAFE_OFFLINE = B.comment("Explicit opt-in: offline UUIDs can be impersonated.").define("allowUnsafeOfflineMode", false);
    public static final ForgeConfigSpec.IntValue MIN_PASSWORD = B.defineInRange("minimumPasswordLength", 12, 8, 256);
    public static final ForgeConfigSpec.IntValue GENERATED_LENGTH = B.defineInRange("generatedPasswordLength", 24, 20, 256);
    public static final ForgeConfigSpec.IntValue MAX_FAILURES = B.defineInRange("maxFailedAttempts", 5, 1, 100);
    public static final ForgeConfigSpec.IntValue FAILURE_WINDOW = B.defineInRange("failedAttemptWindowSeconds", 300, 10, 86400);
    public static final ForgeConfigSpec.IntValue LOCKOUT = B.defineInRange("temporaryLockoutSeconds", 300, 10, 86400);
    public static final ForgeConfigSpec SPEC = B.build();

    private ServerConfig() {}

    public static ValidatedConfig snapshot() {
        return ValidatedConfig.validate(new ValidatedConfig(ENABLED.get(), TIMEOUT.get(), FIRST_JOIN.get(),
                REQUIRE_ONLINE.get(), UNSAFE_OFFLINE.get(), MIN_PASSWORD.get(), GENERATED_LENGTH.get(),
                MAX_FAILURES.get(), FAILURE_WINDOW.get(), LOCKOUT.get()));
    }
}
