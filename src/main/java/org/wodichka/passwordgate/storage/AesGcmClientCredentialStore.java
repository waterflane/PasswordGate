package org.wodichka.passwordgate.storage;

import org.wodichka.passwordgate.security.SecretBytes;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;

public final class AesGcmClientCredentialStore implements ClientCredentialStore {
    private static final int MAGIC=0x50474331, VERSION=1, MAX_FILE=4096;
    private final Path credentialFile,keyFile; private final LocalKeyProtector protector; private final SecureRandom random=new SecureRandom();
    public AesGcmClientCredentialStore(Path directory){this(directory,new WindowsDpapiProtector());}
    AesGcmClientCredentialStore(Path directory,LocalKeyProtector protector){credentialFile=directory.resolve("credential.pgc");keyFile=directory.resolve("masterkey.dpapi");this.protector=protector;}
    @Override public boolean secureStorageAvailable(){return protector.available();}
    @Override public Optional<char[]> load()throws IOException{
        if(!Files.exists(credentialFile))return Optional.empty(); if(!protector.available())throw new IOException("secure system secret storage is unavailable");
        byte[] data=Files.readAllBytes(credentialFile); if(data.length>MAX_FILE)throw new IOException("corrupted local credential storage");
        byte[] key=loadKey(); byte[] plain=null;
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(data))){
            if(in.readInt()!=MAGIC||in.readUnsignedByte()!=VERSION)throw new IOException("unsupported local credential format");
            int nonceLength=in.readUnsignedByte(), cipherLength=in.readUnsignedShort();
            if(nonceLength!=12||cipherLength<16||cipherLength>2048||in.available()!=nonceLength+cipherLength)throw new IOException("corrupted local credential storage");
            byte[] nonce=in.readNBytes(nonceLength),ciphertext=in.readNBytes(cipherLength);
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(new byte[]{VERSION});plain=cipher.doFinal(ciphertext);
            CharBuffer chars=StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plain));char[] out=new char[chars.remaining()];chars.get(out);return Optional.of(out);
        }catch(GeneralSecurityException|RuntimeException e){throw new IOException("corrupted or locked local credential storage",e);}finally{Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);Arrays.fill(data,(byte)0);}
    }
    @Override public void save(char[] password)throws IOException{
        if(!protector.available())throw new IOException("secure system secret storage is unavailable");
        byte[] key=loadOrCreateKey(),plain=SecretBytes.utf8(password),nonce=new byte[12];random.nextBytes(nonce);
        try{Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(new byte[]{VERSION});byte[] encrypted=cipher.doFinal(plain);
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(bytes)){out.writeInt(MAGIC);out.writeByte(VERSION);out.writeByte(nonce.length);out.writeShort(encrypted.length);out.write(nonce);out.write(encrypted);}atomicWrite(credentialFile,bytes.toByteArray());
        }catch(GeneralSecurityException e){throw new IOException("could not encrypt local credential",e);}finally{Arrays.fill(key,(byte)0);Arrays.fill(plain,(byte)0);}
    }
    @Override public void clear()throws IOException{Files.deleteIfExists(credentialFile);}
    private byte[] loadOrCreateKey()throws IOException{if(Files.exists(keyFile))return loadKey();byte[] key=new byte[32];random.nextBytes(key);try{atomicWrite(keyFile,protector.protect(key));return key;}catch(IOException e){Arrays.fill(key,(byte)0);throw e;}}
    private byte[] loadKey()throws IOException{if(!Files.exists(keyFile)||Files.size(keyFile)>1024)throw new IOException("missing or corrupted protected key");byte[] protectedKey=Files.readAllBytes(keyFile);byte[] key=protector.unprotect(protectedKey);Arrays.fill(protectedKey,(byte)0);if(key.length!=32){Arrays.fill(key,(byte)0);throw new IOException("invalid protected key");}return key;}
    private static void atomicWrite(Path file,byte[] data)throws IOException{Files.createDirectories(file.getParent());Path temp=Files.createTempFile(file.getParent(),file.getFileName().toString(),".tmp");try{Files.write(temp,data);restrict(temp);Files.move(temp,file,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);restrict(file);}finally{Files.deleteIfExists(temp);}}
    private static void restrict(Path file){try{Files.setPosixFilePermissions(file,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(IOException|UnsupportedOperationException ignored){}}
}
