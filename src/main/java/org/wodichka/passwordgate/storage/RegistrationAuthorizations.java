package org.wodichka.passwordgate.storage;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class RegistrationAuthorizations {
    private final Path file;private final Set<UUID> ids=ConcurrentHashMap.newKeySet();
    public RegistrationAuthorizations(Path file){this.file=file;}
    public synchronized void load()throws IOException{ids.clear();if(!Files.exists(file))return;if(Files.size(file)>1024*1024)throw new IOException("registration authorization file is too large");try{JsonArray a=JsonParser.parseString(Files.readString(file)).getAsJsonArray();if(a.size()>100_000)throw new IOException("too many authorizations");a.forEach(e->ids.add(UUID.fromString(e.getAsString())));}catch(RuntimeException e){throw new IOException("corrupted registration authorization file",e);}}
    public boolean contains(UUID id){return ids.contains(id);}
    public synchronized void add(UUID id)throws IOException{ids.add(id);write();}
    public synchronized void consume(UUID id){if(ids.remove(id))try{write();}catch(IOException ignored){ids.add(id);}}
    private void write()throws IOException{Files.createDirectories(file.getParent());JsonArray a=new JsonArray();ids.stream().sorted().forEach(id->a.add(id.toString()));Path t=Files.createTempFile(file.getParent(),"authorizations",".tmp");try{Files.writeString(t,a.toString(),StandardCharsets.UTF_8);try{Files.move(t,file,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(t,file,StandardCopyOption.REPLACE_EXISTING);}}finally{Files.deleteIfExists(t);}}
}
