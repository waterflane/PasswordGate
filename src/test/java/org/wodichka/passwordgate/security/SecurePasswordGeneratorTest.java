package org.wodichka.passwordgate.security;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class SecurePasswordGeneratorTest {
    @Test void generatesStrongNonAmbiguousPasswords(){var generator=new SecurePasswordGenerator();Set<String> unique=new HashSet<>();for(int i=0;i<100;i++){char[] p=generator.generate(24);String s=new String(p);assertEquals(24,p.length);assertTrue(s.matches(".*[A-Z].*"));assertTrue(s.matches(".*[a-z].*"));assertTrue(s.matches(".*[0-9].*"));assertTrue(s.matches(".*[!#$%&*+\\-=?@^_].*"));assertFalse(s.matches(".*[0O1Il].*"));unique.add(s);Arrays.fill(p,'\0');}assertEquals(100,unique.size());}
    @Test void rejectsLessThan128Bits(){assertThrows(IllegalArgumentException.class,()->new SecurePasswordGenerator().generate(20));assertEquals(21,new SecurePasswordGenerator().generate(21).length);}
}
