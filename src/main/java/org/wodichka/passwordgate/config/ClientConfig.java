package org.wodichka.passwordgate.config;

import net.neoforged.neoforge.common.ModConfigSpec;

public final class ClientConfig {
    private static final ModConfigSpec.Builder B=new ModConfigSpec.Builder();
    public static final ModConfigSpec.IntValue GENERATED_LENGTH=B.comment("Generated passwords have at least 128 bits of entropy.").defineInRange("generatedPasswordLength",24,21,256);
    public static final ModConfigSpec SPEC=B.build(); private ClientConfig(){}
}
