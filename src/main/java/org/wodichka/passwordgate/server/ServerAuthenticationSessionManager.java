package org.wodichka.passwordgate.server;

import net.minecraft.network.Connection;
import org.wodichka.passwordgate.common.AuthenticationSession;
import org.wodichka.passwordgate.common.AuthenticationSessionManager;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.AuthenticationRateLimiter;
import org.wodichka.passwordgate.security.Srp6aProtocol;
import org.wodichka.passwordgate.storage.ServerCredentialRepository;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

final class ServerAuthenticationSessionManager implements AuthenticationSessionManager {
    private final Map<Connection,ServerAuthenticationSession> sessions=new ConcurrentHashMap<>();
    private final ServerCredentialRepository repository; private final AuthenticationRateLimiter limiter;
    private final ScheduledExecutorService scheduler=Executors.newScheduledThreadPool(2,r->{Thread t=new Thread(r,"PasswordGate scheduler");t.setDaemon(true);return t;});
    private final int timeout,minimumPasswordLength; private final java.util.function.Predicate<UUID> registrationAllowed; private final java.util.function.Consumer<UUID> registrationConsumed;
    ServerAuthenticationSessionManager(ServerCredentialRepository r,AuthenticationRateLimiter l,int timeout,int minimumPasswordLength,java.util.function.Predicate<UUID> registrationAllowed,java.util.function.Consumer<UUID> registrationConsumed){repository=r;limiter=l;this.timeout=timeout;this.minimumPasswordLength=minimumPasswordLength;this.registrationAllowed=registrationAllowed;this.registrationConsumed=registrationConsumed; scheduler.scheduleAtFixedRate(()->limiter.cleanup(System.nanoTime()),5,5,java.util.concurrent.TimeUnit.MINUTES);}
    @Override public AuthenticationSession begin(Connection c,UUID id){
        ServerAuthenticationSession s=new ServerAuthenticationSession(c,id,repository,limiter,new Srp6aProtocol(),scheduler,timeout,minimumPasswordLength,registrationAllowed.test(id),()->registrationConsumed.accept(id),()->{});
        ServerAuthenticationSession old=sessions.put(c,s); if(old!=null)old.close(); s.completion().whenComplete((v,e)->sessions.remove(c,s)); c.channel().closeFuture().addListener(f->disconnected(c)); return s;
    }
    @Override public void receive(Connection c,AuthPacket p,int tx){ServerAuthenticationSession s=sessions.get(c);if(s!=null)s.receive(p,tx);else c.disconnect(net.minecraft.network.chat.Component.translatable("disconnect.passwordgate.malformed_packet"));}
    @Override public void disconnected(Connection c){ServerAuthenticationSession s=sessions.remove(c);if(s!=null)s.close();}
    @Override public void close(){sessions.values().forEach(ServerAuthenticationSession::close);sessions.clear();scheduler.shutdownNow();}
}
