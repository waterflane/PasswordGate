package org.wodichka.passwordgate.server;

import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import org.wodichka.passwordgate.common.AuthenticationSession;
import org.wodichka.passwordgate.network.AuthMessageType;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.AuthenticationRateLimiter;
import org.wodichka.passwordgate.security.PasswordAuthProtocol;
import org.wodichka.passwordgate.security.SecurePasswordGenerator;
import org.wodichka.passwordgate.security.Srp6aProtocol;
import org.wodichka.passwordgate.storage.CredentialRecord;
import org.wodichka.passwordgate.storage.ServerCredentialRepository;
import org.wodichka.passwordgate.PasswordGate;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Consumer;

final class ServerAuthenticationSession implements AuthenticationSession {
    private enum State { STARTING, WAIT_REGISTER, COMPUTING, WAIT_PROOF, WAIT_ACK, PERSISTING, COMPLETE, CLOSED }
    private final UUID id = UUID.randomUUID(), identity;
    private final Connection connection;
    private final byte[] identityBytes;
    private final ServerCredentialRepository repository;
    private final AuthenticationRateLimiter limiter;
    private final PasswordAuthProtocol protocol = new Srp6aProtocol();
    private final Consumer<CustomPacketPayload> sender;
    private final ScheduledExecutorService scheduler;
    private final Executor crypto;
    private final Consumer<Runnable> mainExecutor;
    private final int timeoutSeconds, minimumPasswordLength;
    private final boolean registrationAllowed;
    private final CompletableFuture<Boolean> completion = new CompletableFuture<>();
    private final InetAddress address;
    private final Runnable cleanup, registrationConsumed;
    private State state=State.STARTING;
    private int expectedSequence;
    private byte[] salt;
    private BigInteger pendingVerifier;
    private CredentialRecord existing;
    private boolean fakeAccount;
    private PasswordAuthProtocol.ServerExchange exchange;
    private ScheduledFuture<?> timeout;

    ServerAuthenticationSession(Connection connection, UUID identity, ServerCredentialRepository repository,
            AuthenticationRateLimiter limiter, Consumer<CustomPacketPayload> sender, ScheduledExecutorService scheduler,
            Executor crypto, Consumer<Runnable> mainExecutor, int timeoutSeconds, int minimumPasswordLength,
            boolean registrationAllowed, Runnable registrationConsumed, Runnable cleanup) {
        this.connection=connection;this.identity=identity;this.identityBytes=identity.toString().getBytes(StandardCharsets.UTF_8);
        this.repository=repository;this.limiter=limiter;this.sender=sender;this.scheduler=scheduler;this.crypto=crypto;this.mainExecutor=mainExecutor;
        this.timeoutSeconds=timeoutSeconds;this.minimumPasswordLength=minimumPasswordLength;this.registrationAllowed=registrationAllowed;this.registrationConsumed=registrationConsumed;this.cleanup=cleanup;
        this.address=connection.getRemoteAddress() instanceof InetSocketAddress a?a.getAddress():null;
    }

    UUID identity(){return identity;}
    @Override public UUID id(){return id;}
    @Override public CompletableFuture<Boolean> completion(){return completion;}
    void begin(){mainExecutor.accept(this::start);}

    private synchronized void start(){
        if(state!=State.STARTING)return;
        if(limiter.isLocked(identity,address,System.nanoTime())){fail("disconnect.passwordgate.lockout",false);return;}
        existing=repository.find(identity).orElse(null);
        if(existing==null&&registrationAllowed){salt=new byte[32];new SecureRandom().nextBytes(salt);state=State.WAIT_REGISTER;send(new AuthPacket(id,identity,AuthMessageType.REGISTER_REQUEST,minimumPasswordLength,salt,null));return;}
        if(existing==null){fakeAccount=true;state=State.COMPUTING;CompletableFuture.supplyAsync(this::createFakeRegistration,crypto).whenComplete((registration,error)->mainExecutor.accept(()->{
            synchronized(this){if(state!=State.COMPUTING)return;if(error!=null){fail("disconnect.passwordgate.authentication_failed",false);return;}salt=registration.salt();startChallengeAsync(registration.verifier());}
        }));return;}
        salt=existing.salt();startChallengeAsync(existing.verifier());
    }

    private PasswordAuthProtocol.Registration createFakeRegistration(){char[] dummy=new SecurePasswordGenerator().generate(24);try{return protocol.createRegistration(identityBytes,dummy);}finally{Arrays.fill(dummy,'\0');}}

    @Override public synchronized void receive(AuthPacket p,int sequence){
        if(state==State.CLOSED||state==State.COMPLETE)return;
        if(!id.equals(p.sessionId())||!identity.equals(p.identity())||sequence!=expectedSequence){malformed();return;}
        try{
            if(state==State.WAIT_REGISTER&&p.messageType()==AuthMessageType.REGISTER_SUBMIT){BigInteger verifier=integer(p.first());Srp6aProtocol.validateVerifier(verifier);pendingVerifier=verifier;startChallengeAsync(verifier);return;}
            if(state==State.WAIT_PROOF&&p.messageType()==AuthMessageType.CLIENT_PROOF){verifyProofAsync(integer(p.first()),p.second());return;}
            if(state==State.WAIT_ACK&&p.messageType()==AuthMessageType.ACK){succeed();return;}
            malformed();
        }catch(RuntimeException e){malformed();}
    }

    private synchronized void startChallengeAsync(BigInteger verifier){
        if(state==State.CLOSED)return;state=State.COMPUTING;
        CompletableFuture.supplyAsync(()->protocol.startServer(verifier),crypto).whenComplete((next,error)->mainExecutor.accept(()->{
            synchronized(this){if(state!=State.COMPUTING){if(next!=null)next.close();return;}if(error!=null){PasswordGate.LOGGER.warn("PasswordGate SRP challenge computation failed",error);fail("disconnect.passwordgate.authentication_failed",false);return;}if(exchange!=null)exchange.close();exchange=next;state=State.WAIT_PROOF;send(new AuthPacket(id,identity,AuthMessageType.CHALLENGE,salt,Srp6aProtocol.unsigned(exchange.publicValue())));}
        }));
    }

    private synchronized void verifyProofAsync(BigInteger clientPublic,byte[] proof){
        state=State.COMPUTING;PasswordAuthProtocol.ServerExchange current=exchange;
        CompletableFuture.supplyAsync(()->current.verifyClient(clientPublic,proof),crypto).whenComplete((m2,error)->mainExecutor.accept(()->{
            synchronized(this){if(state!=State.COMPUTING)return;if(error!=null||m2==null||fakeAccount){fail("disconnect.passwordgate.authentication_failed",true);return;}state=State.WAIT_ACK;send(new AuthPacket(id,identity,AuthMessageType.SERVER_PROOF,null,m2));}
        }));
    }

    private void send(AuthPacket packet){
        expectedSequence=expectedSequence==Integer.MAX_VALUE?1:expectedSequence+1;
        sender.accept(packet.withSequence(expectedSequence));
        if(timeout==null)timeout=scheduler.schedule(this::timeout,timeoutSeconds,TimeUnit.SECONDS);
    }

    private synchronized void succeed(){
        state=State.PERSISTING;if(timeout!=null)timeout.cancel(false);limiter.recordSuccess(identity,address);
        long now=Instant.now().toEpochMilli();CredentialRecord record=existing==null?new CredentialRecord(1,1,identity,salt,pendingVerifier,now,now,0):existing.authenticated(now);
        repository.save(record).whenComplete((v,error)->mainExecutor.accept(()->{synchronized(this){if(state!=State.PERSISTING)return;if(error==null){if(existing==null)registrationConsumed.run();state=State.COMPLETE;completion.complete(true);}else{disconnect(Component.translatable("disconnect.passwordgate.server_storage_error"));state=State.CLOSED;completion.complete(false);}clearSecrets();cleanup.run();}}));
    }

    void rejectDuplicate(){mainExecutor.accept(()->fail("disconnect.passwordgate.duplicate_connection",false));}
    void abort(){
        boolean disconnect;
        synchronized(this){disconnect=state!=State.COMPLETE&&state!=State.CLOSED;}
        close();
        if(disconnect&&connection.isConnected())mainExecutor.accept(()->disconnect(Component.translatable("disconnect.passwordgate.authentication_failed")));
    }
    private void malformed(){fail("disconnect.passwordgate.malformed_packet",true);}
    private synchronized void fail(String key,boolean count){
        if(state==State.CLOSED||state==State.COMPLETE)return;state=State.CLOSED;if(timeout!=null)timeout.cancel(false);if(count)limiter.recordFailure(identity,address,System.nanoTime());
        long delay=count?150L+new SecureRandom().nextInt(201):0L;
        scheduler.schedule(()->mainExecutor.accept(()->{disconnect(Component.translatable(key));completion.complete(false);cleanup.run();}),delay,TimeUnit.MILLISECONDS);clearSecrets();
    }
    @Override public synchronized void timeout(){if(state!=State.COMPLETE&&state!=State.CLOSED)fail("disconnect.passwordgate.timeout",true);}
    @Override public synchronized void close(){if(state!=State.COMPLETE)state=State.CLOSED;if(timeout!=null)timeout.cancel(false);clearSecrets();completion.complete(false);cleanup.run();}
    private void clearSecrets(){if(exchange!=null)exchange.close();exchange=null;if(salt!=null)Arrays.fill(salt,(byte)0);salt=null;pendingVerifier=null;}
    private static BigInteger integer(byte[] bytes){if(bytes.length==0||bytes.length>Srp6aProtocol.MAX_INTEGER_BYTES)throw new IllegalArgumentException();return new BigInteger(1,bytes);}
    private void disconnect(Component reason){connection.disconnect(reason);}
}
