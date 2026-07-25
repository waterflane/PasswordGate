package org.wodichka.passwordgate.server;

import com.mojang.authlib.GameProfile;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.Connection;
import net.minecraft.server.MinecraftServer;
import net.minecraft.world.level.storage.LevelResource;
import org.wodichka.passwordgate.PasswordGate;
import org.wodichka.passwordgate.common.AuthenticationSession;
import org.wodichka.passwordgate.config.ServerConfig;
import org.wodichka.passwordgate.config.ValidatedConfig;
import org.wodichka.passwordgate.network.AuthPacket;
import org.wodichka.passwordgate.security.WindowRateLimiter;
import org.wodichka.passwordgate.storage.JsonCredentialRepository;
import org.wodichka.passwordgate.storage.ServerCredentialRepository;
import org.wodichka.passwordgate.storage.RegistrationAuthorizations;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

public final class ServerRuntime {
    private static volatile ServerCredentialRepository repository; private static volatile RegistrationAuthorizations authorizations; private static volatile ServerAuthenticationSessionManager sessions; private static volatile MinecraftServer server;
    private ServerRuntime(){}
    public static synchronized void start(MinecraftServer minecraftServer)throws IOException{
        stop();server=minecraftServer;ValidatedConfig c=ServerConfig.snapshot();
        var directory=minecraftServer.getWorldPath(LevelResource.ROOT).resolve("passwordgate");JsonCredentialRepository repo=new JsonCredentialRepository(directory.resolve("credentials.json"));repo.load();repository=repo;RegistrationAuthorizations auth=new RegistrationAuthorizations(directory.resolve("registration-authorizations.json"));auth.load();authorizations=auth;
        boolean registration=c.allowFirstJoinRegistration();
        if(!minecraftServer.usesAuthentication()&&!minecraftServer.isSingleplayer()){
            PasswordGate.LOGGER.warn("PasswordGate: server is in offline-mode; UUID impersonation is possible. First-join registration is {}.",registration?"enabled":"disabled");
        }
        sessions=new ServerAuthenticationSessionManager(repo,new WindowRateLimiter(c.maxFailedAttempts(),c.failedAttemptWindowSeconds(),c.temporaryLockoutSeconds()),c.authenticationTimeoutSeconds(),c.minimumPasswordLength(),id->registration||auth.contains(id),auth::consume);
        PasswordGate.LOGGER.info("PasswordGate loaded {} credential record(s)",repo.registeredUuids().size());
    }
    public static AuthenticationSession begin(Connection connection,GameProfile profile){
        ServerAuthenticationSessionManager manager=sessions;if(manager==null)throw new IllegalStateException("PasswordGate server is not ready");
        UUID uuid=profile.getId()!=null?profile.getId():UUIDUtil.createOfflinePlayerUUID(profile.getName());return manager.begin(connection,uuid);
    }
    public static void receive(Connection c,AuthPacket p,int tx){ServerAuthenticationSessionManager manager=sessions;if(manager!=null)manager.receive(c,p,tx);else c.disconnect(net.minecraft.network.chat.Component.translatable("disconnect.passwordgate.server_storage_error"));}
    public static Optional<org.wodichka.passwordgate.storage.CredentialRecord> find(UUID id){return repository==null?Optional.empty():repository.find(id);}
    public static java.util.concurrent.CompletableFuture<Boolean> revoke(UUID id){return repository==null?java.util.concurrent.CompletableFuture.completedFuture(false):repository.remove(id);}
    public static void authorize(UUID id)throws IOException{if(authorizations==null)throw new IOException("server is not ready");authorizations.add(id);}
    public static synchronized void stop(){if(sessions!=null)sessions.close();sessions=null;if(repository!=null)repository.close();repository=null;authorizations=null;server=null;}
}
