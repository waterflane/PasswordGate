package org.wodichka.passwordgate.config;

import net.minecraftforge.common.ForgeConfigSpec;

public final class ClientConfig {
    private static final ForgeConfigSpec.Builder B=new ForgeConfigSpec.Builder();
    public static final ForgeConfigSpec.IntValue GENERATED_LENGTH=B.comment("Generated passwords have at least 128 bits of entropy.").defineInRange("generatedPasswordLength",24,20,256);
    public static final ForgeConfigSpec SPEC=B.build(); private ClientConfig(){}
}
