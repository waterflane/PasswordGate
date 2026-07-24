package org.wodichka.passwordgate.server;

import net.minecraft.network.Connection;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import org.wodichka.passwordgate.common.AuthenticationSession;
import org.wodichka.passwordgate.common.AuthenticationSessionManager;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.AuthenticationRateLimiter;
import org.wodichka.passwordgate.storage.ServerCredentialRepository;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Consumer;

final class ServerAuthenticationSessionManager implements AuthenticationSessionManager {
    private final Map<Connection,ServerAuthenticationSession> sessions=new ConcurrentHashMap<>();
    private final Map<UUID,ServerAuthenticationSession> identities=new ConcurrentHashMap<>();
    private final ServerCredentialRepository repository;
    private final AuthenticationRateLimiter limiter;
    private final ScheduledExecutorService scheduler=Executors.newScheduledThreadPool(2,r->{Thread t=new Thread(r,"PasswordGate scheduler");t.setDaemon(true);return t;});
    private final ExecutorService crypto=Executors.newFixedThreadPool(Math.max(2,Runtime.getRuntime().availableProcessors()/2),r->{Thread t=new Thread(r,"PasswordGate SRP worker");t.setDaemon(true);return t;});
    private final int timeout,minimumPasswordLength;
    private final java.util.function.Predicate<UUID> registrationAllowed;
    private final java.util.function.Consumer<UUID> registrationConsumed;
    private final Consumer<Runnable> mainExecutor;

    ServerAuthenticationSessionManager(ServerCredentialRepository r, AuthenticationRateLimiter l, int timeout, int minimumPasswordLength,
            java.util.function.Predicate<UUID> registrationAllowed, java.util.function.Consumer<UUID> registrationConsumed, Consumer<Runnable> mainExecutor) {
        repository=r;limiter=l;this.timeout=timeout;this.minimumPasswordLength=minimumPasswordLength;this.registrationAllowed=registrationAllowed;this.registrationConsumed=registrationConsumed;this.mainExecutor=mainExecutor;
        scheduler.scheduleAtFixedRate(()->limiter.cleanup(System.nanoTime()),5,5,TimeUnit.MINUTES);
    }

    @Override public AuthenticationSession begin(Connection c, UUID id, Consumer<CustomPacketPayload> sender) {
        ServerAuthenticationSession s=new ServerAuthenticationSession(c,id,repository,limiter,sender,scheduler,crypto,mainExecutor,timeout,minimumPasswordLength,registrationAllowed.test(id),()->registrationConsumed.accept(id),()->cleanup(c,id));
        ServerAuthenticationSession duplicate=identities.putIfAbsent(id,s);
        if(duplicate!=null){s.rejectDuplicate();return s;}
        ServerAuthenticationSession old=sessions.put(c,s); if(old!=null)old.close();
        c.channel().closeFuture().addListener(f->disconnected(c));
        s.begin();
        return s;
    }
    private void cleanup(Connection c,UUID id){ServerAuthenticationSession s=sessions.remove(c);if(s!=null)identities.remove(id,s);}
    @Override public void receive(Connection c,AuthPacket p,int ignored){receive(c,p);}
    void receive(Connection c,AuthPacket p){ServerAuthenticationSession s=sessions.get(c);if(s!=null)s.receive(p,p.sequence());else c.disconnect(net.minecraft.network.chat.Component.translatable("disconnect.passwordgate.malformed_packet"));}
    @Override public void disconnected(Connection c){ServerAuthenticationSession s=sessions.remove(c);if(s!=null){identities.remove(s.identity(),s);s.close();}}
    @Override public void close(){sessions.values().forEach(ServerAuthenticationSession::close);sessions.clear();identities.clear();scheduler.shutdownNow();crypto.shutdownNow();}
}
