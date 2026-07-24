package org.wodichka.passwordgate.commands;

import com.mojang.authlib.GameProfile;
import com.mojang.brigadier.CommandDispatcher;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.arguments.GameProfileArgument;
import net.minecraft.network.chat.Component;
import org.wodichka.passwordgate.server.ServerRuntime;

import java.util.Collection;

public final class PasswordGateCommands {
    private PasswordGateCommands(){}
    public static void register(CommandDispatcher<CommandSourceStack> d){
        d.register(Commands.literal("passwordgate").requires(s->s.hasPermission(2))
                .then(Commands.literal("status").then(Commands.argument("player",GameProfileArgument.gameProfile()).executes(c->status(c.getSource(),GameProfileArgument.getGameProfiles(c,"player")))))
                .then(Commands.literal("reset").then(Commands.argument("player",GameProfileArgument.gameProfile()).executes(c->revoke(c.getSource(),GameProfileArgument.getGameProfiles(c,"player"),"command.passwordgate.reset"))))
                .then(Commands.literal("revoke").then(Commands.argument("player",GameProfileArgument.gameProfile()).executes(c->revoke(c.getSource(),GameProfileArgument.getGameProfiles(c,"player"),"command.passwordgate.revoke"))))
                .then(Commands.literal("authorize").then(Commands.argument("player",GameProfileArgument.gameProfile()).executes(c->authorize(c.getSource(),GameProfileArgument.getGameProfiles(c,"player")))))
                .then(Commands.literal("reload").executes(c->{ServerRuntime.reloadFromConfig();c.getSource().sendSuccess(()->Component.translatable("command.passwordgate.reload"),true);return 1;})));
    }
    private static int status(CommandSourceStack source,Collection<GameProfile> profiles){for(GameProfile p:profiles){boolean registered=p.getId()!=null&&ServerRuntime.find(p.getId()).isPresent();source.sendSuccess(()->Component.translatable(registered?"command.passwordgate.status.registered":"command.passwordgate.status.unregistered",p.getName()),false);}return profiles.size();}
    private static int revoke(CommandSourceStack source,Collection<GameProfile> profiles,String key){for(GameProfile p:profiles)if(p.getId()!=null)ServerRuntime.revoke(p.getId()).whenComplete((removed,error)->source.getServer().execute(()->source.sendSuccess(()->Component.translatable(key,p.getName()),true)));return profiles.size();}
    private static int authorize(CommandSourceStack source,Collection<GameProfile> profiles){int count=0;for(GameProfile p:profiles)if(p.getId()!=null)try{ServerRuntime.authorize(p.getId());source.sendSuccess(()->Component.translatable("command.passwordgate.authorize",p.getName()),true);count++;}catch(java.io.IOException e){source.sendFailure(Component.translatable("command.passwordgate.storage_error"));}return count;}
}
