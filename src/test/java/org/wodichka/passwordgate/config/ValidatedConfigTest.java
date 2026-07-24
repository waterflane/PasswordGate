package org.wodichka.passwordgate.config;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class ValidatedConfigTest {@Test void clampsEveryNumericRange(){var c=ValidatedConfig.validate(new ValidatedConfig(true,1,true,true,false,1,1,0,1,999999));assertEquals(5,c.authenticationTimeoutSeconds());assertEquals(8,c.minimumPasswordLength());assertEquals(21,c.generatedPasswordLength());assertEquals(1,c.maxFailedAttempts());assertEquals(10,c.failedAttemptWindowSeconds());assertEquals(86400,c.temporaryLockoutSeconds());}}
