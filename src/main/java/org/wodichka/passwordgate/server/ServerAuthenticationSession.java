package org.wodichka.passwordgate.server;

import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import org.wodichka.passwordgate.common.AuthenticationSession;
import org.wodichka.passwordgate.network.AuthMessageType;
import org.wodichka.passwordgate.network.AuthNetwork;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.AuthenticationRateLimiter;
import org.wodichka.passwordgate.security.PasswordAuthProtocol;
import org.wodichka.passwordgate.security.Srp6aProtocol;
import org.wodichka.passwordgate.storage.CredentialRecord;
import org.wodichka.passwordgate.storage.ServerCredentialRepository;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

final class ServerAuthenticationSession implements AuthenticationSession {
    private enum State { WAIT_REGISTER, WAIT_PROOF, WAIT_ACK, COMPLETE, CLOSED }
    private final UUID id = UUID.randomUUID(), identity;
    private final Connection connection;
    private final byte[] identityBytes;
    private final ServerCredentialRepository repository;
    private final AuthenticationRateLimiter limiter;
    private final PasswordAuthProtocol protocol;
    private final ScheduledExecutorService scheduler;
    private final CompletableFuture<Void> completion = new CompletableFuture<>();
    private final InetAddress address;
    private final Runnable cleanup;
    private final Runnable registrationConsumed;
    private State state;
    private int expectedTransaction;
    private byte[] salt;
    private BigInteger pendingVerifier;
    private CredentialRecord existing;
    private boolean fakeAccount;
    private PasswordAuthProtocol.ServerExchange exchange;
    private ScheduledFuture<?> timeout;

    ServerAuthenticationSession(Connection connection, UUID identity, ServerCredentialRepository repository,
                                AuthenticationRateLimiter limiter, PasswordAuthProtocol protocol,
                                ScheduledExecutorService scheduler, int timeoutSeconds,int minimumPasswordLength,
                                boolean registrationAllowed, Runnable registrationConsumed, Runnable cleanup) {
        this.connection=connection; this.identity=identity; this.identityBytes=identity.toString().getBytes(StandardCharsets.UTF_8);
        this.repository=repository; this.limiter=limiter; this.protocol=protocol; this.scheduler=scheduler; this.registrationConsumed=registrationConsumed; this.cleanup=cleanup;
        this.address = connection.getRemoteAddress() instanceof InetSocketAddress a ? a.getAddress() : null;
        if (limiter.isLocked(identity, address, System.nanoTime())) { fail("disconnect.passwordgate.lockout", false); return; }
        existing = repository.find(identity).orElse(null);
        if (existing == null) {
            if (!registrationAllowed) {
                fakeAccount=true;char[] dummy=new org.wodichka.passwordgate.security.SecurePasswordGenerator().generate(24);
                try{var registration=protocol.createRegistration(identityBytes,dummy);salt=registration.salt();startChallenge(registration.verifier());}finally{java.util.Arrays.fill(dummy,'\0');}
            } else { salt = new byte[32]; new SecureRandom().nextBytes(salt); state=State.WAIT_REGISTER; send(new AuthPacket(id, identity, AuthMessageType.REGISTER_REQUEST,minimumPasswordLength, salt, null)); }
        } else {
            salt=existing.salt(); startChallenge(existing.verifier());
        }
        timeout = scheduler.schedule(this::timeout, timeoutSeconds, TimeUnit.SECONDS);
    }

    @Override public UUID id(){return id;} @Override public CompletableFuture<Void> completion(){return completion;}

    @Override public synchronized void receive(AuthPacket p, int transaction) {
        if (state == State.CLOSED || state == State.COMPLETE) return;
        if (!id.equals(p.sessionId()) || !identity.equals(p.identity()) || transaction != expectedTransaction) { malformed(); return; }
        try {
            if (state == State.WAIT_REGISTER && p.type() == AuthMessageType.REGISTER_SUBMIT) {
                BigInteger verifier = integer(p.first()); Srp6aProtocol.validateVerifier(verifier); pendingVerifier=verifier; startChallenge(verifier); return;
            }
            if (state == State.WAIT_PROOF && p.type() == AuthMessageType.CLIENT_PROOF) {
                byte[] m2 = exchange.verifyClient(integer(p.first()), p.second());
                if (m2 == null || fakeAccount) { fail("disconnect.passwordgate.authentication_failed", true); return; }
                state=State.WAIT_ACK; send(new AuthPacket(id, identity, AuthMessageType.SERVER_PROOF, null, m2)); return;
            }
            if (state == State.WAIT_ACK && p.type() == AuthMessageType.ACK) { succeed(); return; }
            malformed();
        } catch (RuntimeException e) { malformed(); }
    }

    private void startChallenge(BigInteger verifier) {
        if (exchange != null) exchange.close(); exchange=protocol.startServer(verifier); state=State.WAIT_PROOF;
        send(new AuthPacket(id, identity, AuthMessageType.CHALLENGE, salt, Srp6aProtocol.unsigned(exchange.publicValue())));
    }
    private void send(AuthPacket packet) { expectedTransaction=AuthNetwork.nextTransaction(); AuthNetwork.sendLogin(connection, packet, expectedTransaction); }
    private static BigInteger integer(byte[] bytes) { if(bytes.length==0||bytes.length>Srp6aProtocol.MAX_INTEGER_BYTES) throw new IllegalArgumentException(); return new BigInteger(1,bytes); }

    private void succeed() {
        state=State.COMPLETE; if(timeout!=null) timeout.cancel(false); limiter.recordSuccess(identity,address);
        long now=Instant.now().toEpochMilli();
        CredentialRecord record = existing == null ? new CredentialRecord(1,1,identity,salt,pendingVerifier,now,now,0) : existing.authenticated(now);
        if(existing==null)registrationConsumed.run();
        repository.save(record).whenComplete((v,error)-> {
            if(error==null) completion.complete(null); else { disconnect(Component.translatable("disconnect.passwordgate.server_storage_error")); completion.complete(null); }
            close();
        });
    }
    private void malformed(){ fail("disconnect.passwordgate.malformed_packet", true); }
    private synchronized void fail(String key, boolean count) {
        if(state==State.CLOSED||state==State.COMPLETE)return; state=State.CLOSED; if(timeout!=null)timeout.cancel(false);
        if(count) limiter.recordFailure(identity,address,System.nanoTime());
        long delay=count ? 150L + new SecureRandom().nextInt(201) : 0L;
        scheduler.schedule(()->{ disconnect(Component.translatable(key)); completion.complete(null); cleanup.run(); },delay,TimeUnit.MILLISECONDS);
        clearSecrets();
    }
    @Override public synchronized void timeout(){ if(state!=State.COMPLETE&&state!=State.CLOSED) fail("disconnect.passwordgate.timeout",true); }
    @Override public synchronized void close(){ if(state!=State.COMPLETE)state=State.CLOSED; if(timeout!=null)timeout.cancel(false); clearSecrets(); completion.complete(null); cleanup.run(); }
    private void clearSecrets(){ if(exchange!=null)exchange.close(); exchange=null; if(salt!=null)java.util.Arrays.fill(salt,(byte)0); salt=null; pendingVerifier=null; }
    private void disconnect(Component reason){if(connection.getPacketListener() instanceof net.minecraft.server.network.ServerLoginPacketListenerImpl login)login.disconnect(reason);else connection.disconnect(reason);}
}
