package org.wodichka.passwordgate.server;

import io.netty.channel.embedded.EmbeddedChannel;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.PacketFlow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.wodichka.passwordgate.network.AuthMessageType;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.Srp6aProtocol;
import org.wodichka.passwordgate.security.WindowRateLimiter;
import org.wodichka.passwordgate.storage.CredentialRecord;
import org.wodichka.passwordgate.storage.ServerCredentialRepository;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurationAuthenticationIntegrationTest {
    private final ScheduledExecutorService scheduler=Executors.newSingleThreadScheduledExecutor();
    @AfterEach void stop(){scheduler.shutdownNow();}

    @Test void existingAccountDoesNotCompleteConfigurationUntilMutualProofAndAck(){
        UUID id=UUID.randomUUID();char[] password="configuration-phase-password".toCharArray();byte[] identity=id.toString().getBytes(StandardCharsets.UTF_8);
        var protocol=new Srp6aProtocol();var registration=protocol.createRegistration(identity,password);var repository=new MemoryRepository(new CredentialRecord(1,1,id,registration.salt(),registration.verifier(),1,1,0));
        Harness h=start(id,repository,false);AuthPacket challenge=h.take(AuthMessageType.CHALLENGE);
        assertFalse(h.session.completion().isDone(),"configuration task must still gate JoinWorld");
        try(var client=protocol.startClient(identity,password,challenge.first(),new java.math.BigInteger(1,challenge.second()))){
            h.session.receive(new AuthPacket(challenge.sessionId(),id,AuthMessageType.CLIENT_PROOF,Srp6aProtocol.unsigned(client.publicValue()),client.clientProof()).withSequence(challenge.sequence()),challenge.sequence());
            AuthPacket serverProof=h.take(AuthMessageType.SERVER_PROOF);assertTrue(client.verifyServerProof(serverProof.second()));
            assertFalse(h.session.completion().isDone(),"server proof alone must not release configuration");
            h.session.receive(new AuthPacket(serverProof.sessionId(),id,AuthMessageType.ACK,null,null).withSequence(serverProof.sequence()),serverProof.sequence());
        }
        assertTrue(h.session.completion().join());assertNotNull(repository.record);assertTrue(repository.record.lastAuthenticatedAt()>1);
    }

    @Test void firstRegistrationIsPersistedOnlyAfterImmediateSrpAuthentication(){
        UUID id=UUID.randomUUID();char[] password="first-registration-password".toCharArray();byte[] identity=id.toString().getBytes(StandardCharsets.UTF_8);var protocol=new Srp6aProtocol();var repository=new MemoryRepository(null);Harness h=start(id,repository,true);
        AuthPacket request=h.take(AuthMessageType.REGISTER_REQUEST);var registration=protocol.createRegistration(identity,password,request.first());
        h.session.receive(new AuthPacket(request.sessionId(),id,AuthMessageType.REGISTER_SUBMIT,Srp6aProtocol.unsigned(registration.verifier()),null).withSequence(request.sequence()),request.sequence());
        assertNull(repository.record);AuthPacket challenge=h.take(AuthMessageType.CHALLENGE);
        try(var client=protocol.startClient(identity,password,challenge.first(),new java.math.BigInteger(1,challenge.second()))){
            h.session.receive(new AuthPacket(challenge.sessionId(),id,AuthMessageType.CLIENT_PROOF,Srp6aProtocol.unsigned(client.publicValue()),client.clientProof()).withSequence(challenge.sequence()),challenge.sequence());
            AuthPacket proof=h.take(AuthMessageType.SERVER_PROOF);assertTrue(client.verifyServerProof(proof.second()));assertNull(repository.record);
            h.session.receive(new AuthPacket(proof.sessionId(),id,AuthMessageType.ACK,null,null).withSequence(proof.sequence()),proof.sequence());
        }
        assertTrue(h.session.completion().join());assertEquals(registration.verifier(),repository.record.verifier());
    }

    @Test void abortCompletesConfigurationAsFailedInsteadOfLeavingItPending(){
        UUID id=UUID.randomUUID();Harness h=start(id,new MemoryRepository(null),true);
        h.take(AuthMessageType.REGISTER_REQUEST);h.session.abort();
        assertFalse(h.session.completion().join());
    }

    private Harness start(UUID id,MemoryRepository repository,boolean registrationAllowed){
        Connection connection=new Connection(PacketFlow.SERVERBOUND);new EmbeddedChannel(connection);List<AuthPacket> sent=new ArrayList<>();
        var session=new ServerAuthenticationSession(connection,id,repository,new WindowRateLimiter(5,300,300),p->sent.add((AuthPacket)p),scheduler,Runnable::run,Runnable::run,15,12,registrationAllowed,()->{},()->{});
        session.begin();return new Harness(session,sent);
    }
    private record Harness(ServerAuthenticationSession session,List<AuthPacket> sent){AuthPacket take(AuthMessageType type){long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(sent.isEmpty()&&System.nanoTime()<end){try{Thread.sleep(2);}catch(InterruptedException e){Thread.currentThread().interrupt();fail(e);}}assertFalse(sent.isEmpty(),"expected "+type);AuthPacket p=sent.removeFirst();assertEquals(type,p.messageType());return p;}}
    private static final class MemoryRepository implements ServerCredentialRepository {
        private CredentialRecord record;MemoryRepository(CredentialRecord record){this.record=record;}
        public void load(){} public Optional<CredentialRecord> find(UUID id){return Optional.ofNullable(record).filter(r->r.uuid().equals(id));}
        public CompletableFuture<Void> save(CredentialRecord value){record=value;return CompletableFuture.completedFuture(null);}
        public CompletableFuture<Boolean> remove(UUID id){boolean found=record!=null&&record.uuid().equals(id);if(found)record=null;return CompletableFuture.completedFuture(found);}
        public Collection<UUID> registeredUuids(){return record==null?List.of():List.of(record.uuid());} public void close(){}
    }
}
