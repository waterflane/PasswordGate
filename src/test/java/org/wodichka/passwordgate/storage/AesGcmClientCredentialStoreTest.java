package org.wodichka.passwordgate.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class AesGcmClientCredentialStoreTest {
    @TempDir Path dir;
    private static final LocalKeyProtector TEST_PROTECTOR=new LocalKeyProtector(){public boolean available(){return true;}public byte[] protect(byte[] v){return v.clone();}public byte[] unprotect(byte[] v){return v.clone();}};
    @Test void encryptsWithFreshNonceAndRoundTrips()throws Exception{var store=new AesGcmClientCredentialStore(dir,TEST_PROTECTOR);char[] p="local-secret-password".toCharArray();store.save(p);byte[] first=Files.readAllBytes(dir.resolve("credential.pgc"));assertArrayEquals(p,store.load().orElseThrow());store.save(p);byte[] second=Files.readAllBytes(dir.resolve("credential.pgc"));assertFalse(Arrays.equals(first,second));assertFalse(new String(second,java.nio.charset.StandardCharsets.UTF_8).contains(new String(p)));}
    @Test void corruptedCiphertextIsRejected()throws Exception{var store=new AesGcmClientCredentialStore(dir,TEST_PROTECTOR);store.save("local-secret-password".toCharArray());Path file=dir.resolve("credential.pgc");byte[] data=Files.readAllBytes(file);data[data.length-1]^=1;Files.write(file,data);assertThrows(IOException.class,store::load);}
    @Test void refusesUnavailableSecretStore(){var store=new AesGcmClientCredentialStore(dir,new LocalKeyProtector(){public boolean available(){return false;}public byte[] protect(byte[]v)throws IOException{throw new IOException();}public byte[] unprotect(byte[]v)throws IOException{throw new IOException();}});assertThrows(IOException.class,()->store.save("password-password".toCharArray()));}
}
