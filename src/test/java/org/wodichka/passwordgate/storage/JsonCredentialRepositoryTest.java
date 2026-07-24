package org.wodichka.passwordgate.storage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.wodichka.passwordgate.security.Srp6aProtocol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class JsonCredentialRepositoryTest {
    @TempDir Path dir;
    @Test void serializesAndAtomicallyReplaces()throws Exception{Path file=dir.resolve("credentials.json");UUID id=UUID.randomUUID();var p=new Srp6aProtocol();var reg=p.createRegistration(id.toString().getBytes(),"password-password".toCharArray());try(var repo=new JsonCredentialRepository(file)){repo.load();repo.save(new CredentialRecord(1,1,id,reg.salt(),reg.verifier(),1,2,0)).join();assertTrue(Files.exists(file));assertEquals(0,Files.list(dir).filter(x->x.getFileName().toString().endsWith(".tmp")).count());}try(var loaded=new JsonCredentialRepository(file)){loaded.load();assertEquals(reg.verifier(),loaded.find(id).orElseThrow().verifier());}}
    @Test void rejectsCorruptionAndOversize()throws Exception{Path file=dir.resolve("bad.json");Files.writeString(file,"{not json");try(var repo=new JsonCredentialRepository(file)){assertThrows(java.io.IOException.class,repo::load);}Files.write(file,new byte[(int)JsonCredentialRepository.MAX_FILE_SIZE+1]);try(var repo=new JsonCredentialRepository(file)){assertThrows(java.io.IOException.class,repo::load);}}
    @Test void migratesVersionZero()throws Exception{UUID id=UUID.randomUUID();var reg=new Srp6aProtocol().createRegistration(id.toString().getBytes(),"password-password".toCharArray());String json="{\"formatVersion\":0,\"accounts\":[{\"schemeVersion\":1,\"uuid\":\""+id+"\",\"salt\":\""+Base64.getEncoder().encodeToString(reg.salt())+"\",\"verifier\":\""+Base64.getEncoder().encodeToString(Srp6aProtocol.unsigned(reg.verifier()))+"\",\"registeredAt\":1,\"lastAuthenticatedAt\":2}]}";Path file=dir.resolve("legacy.json");Files.writeString(file,json);try(var repo=new JsonCredentialRepository(file)){repo.load();assertEquals(1,repo.find(id).orElseThrow().formatVersion());assertEquals(0,repo.find(id).orElseThrow().failedAttempts());}}
    @Test void readsRealForge1201ServerFixtureAndRejectsFutureVersion()throws Exception{
        Path file=dir.resolve("credentials.json");try(var in=getClass().getResourceAsStream("/fixtures/forge-1.20.1-server-credentials-v0.json")){assertNotNull(in);Files.copy(in,file);}
        UUID id=UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8");try(var repo=new JsonCredentialRepository(file)){repo.load();var record=repo.find(id).orElseThrow();assertEquals(java.math.BigInteger.TWO,record.verifier());assertEquals(1,record.formatVersion());}
        Files.writeString(file,"{\"formatVersion\":999,\"accounts\":[]}");try(var repo=new JsonCredentialRepository(file)){assertThrows(java.io.IOException.class,repo::load);}
    }
}
