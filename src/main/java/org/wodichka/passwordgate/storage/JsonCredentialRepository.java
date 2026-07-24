package org.wodichka.passwordgate.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.wodichka.passwordgate.security.Srp6aProtocol;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class JsonCredentialRepository implements ServerCredentialRepository {
    static final long MAX_FILE_SIZE = 8L * 1024 * 1024;
    private final Path file;
    private final Map<UUID, CredentialRecord> records = new ConcurrentHashMap<>();
    private final ExecutorService writer = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "PasswordGate credential writer"); t.setDaemon(true); return t;
    });
    private final Object writeLock = new Object();
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public JsonCredentialRepository(Path file) { this.file = file; }

    @Override public void load() throws IOException {
        records.clear();
        if (!Files.exists(file)) return;
        long size = Files.size(file);
        if (size <= 0 || size > MAX_FILE_SIZE) throw new IOException("credential file has invalid size");
        try {
            JsonObject root = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
            int storeVersion=requiredInt(root, "formatVersion");
            if (storeVersion != 0 && storeVersion != 1) throw new IOException("unsupported credential store version");
            JsonArray array = root.getAsJsonArray("accounts");
            if (array == null || array.size() > 100_000) throw new IOException("invalid account array");
            for (JsonElement element : array) {
                CredentialRecord record = decode(element.getAsJsonObject(),storeVersion==0);
                if (records.putIfAbsent(record.uuid(), record) != null) throw new IOException("duplicate UUID");
            }
        } catch (RuntimeException e) { throw new IOException("corrupted PasswordGate credential store", e); }
    }

    @Override public Optional<CredentialRecord> find(UUID uuid) { return Optional.ofNullable(records.get(uuid)); }
    @Override public Collection<UUID> registeredUuids() { return new ArrayList<>(records.keySet()); }
    @Override public CompletableFuture<Void> save(CredentialRecord record) {
        records.put(record.uuid(), record);
        return CompletableFuture.runAsync(this::writeUnchecked, writer);
    }
    @Override public CompletableFuture<Boolean> remove(UUID uuid) {
        boolean removed = records.remove(uuid) != null;
        return CompletableFuture.supplyAsync(() -> { if (removed) writeUnchecked(); return removed; }, writer);
    }

    private void writeUnchecked() {
        try { writeNow(); } catch (IOException e) { throw new RuntimeException("could not persist PasswordGate credentials", e); }
    }
    void writeNow() throws IOException {
        synchronized (writeLock) {
            Files.createDirectories(file.getParent());
            JsonObject root = new JsonObject(); root.addProperty("formatVersion", 1);
            JsonArray accounts = new JsonArray(); records.values().stream().sorted((a,b)->a.uuid().compareTo(b.uuid())).map(this::encode).forEach(accounts::add);
            root.add("accounts", accounts);
            byte[] bytes = gson.toJson(root).getBytes(StandardCharsets.UTF_8);
            if (bytes.length > MAX_FILE_SIZE) throw new IOException("credential store exceeds maximum size");
            Path temp = Files.createTempFile(file.getParent(), file.getFileName().toString(), ".tmp");
            try {
                Files.write(temp, bytes);
                try { Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
                catch (AtomicMoveNotSupportedException e) { Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING); }
            } finally { Files.deleteIfExists(temp); }
        }
    }

    private JsonObject encode(CredentialRecord r) {
        JsonObject o = new JsonObject(); o.addProperty("formatVersion", r.formatVersion()); o.addProperty("schemeVersion", r.schemeVersion());
        o.addProperty("uuid", r.uuid().toString()); o.addProperty("salt", Base64.getEncoder().encodeToString(r.salt()));
        o.addProperty("verifier", Base64.getEncoder().encodeToString(Srp6aProtocol.unsigned(r.verifier())));
        o.addProperty("registeredAt", r.registeredAt()); o.addProperty("lastAuthenticatedAt", r.lastAuthenticatedAt()); o.addProperty("failedAttempts", r.failedAttempts()); return o;
    }
    private CredentialRecord decode(JsonObject o,boolean legacy) throws IOException {
        byte[] salt = decodeBase64(o, "salt", 32, 32); byte[] verifier = decodeBase64(o, "verifier", 1, Srp6aProtocol.MAX_INTEGER_BYTES);
        try { return new CredentialRecord(1, requiredInt(o,"schemeVersion"), UUID.fromString(o.get("uuid").getAsString()), salt,
                    new BigInteger(1, verifier), requiredLong(o,"registeredAt"), requiredLong(o,"lastAuthenticatedAt"), legacy||!o.has("failedAttempts")?0:requiredInt(o,"failedAttempts")); }
        catch (RuntimeException e) { throw new IOException("invalid credential entry", e); }
    }
    private static byte[] decodeBase64(JsonObject o, String name, int min, int max) throws IOException {
        try { byte[] b = Base64.getDecoder().decode(o.get(name).getAsString()); if (b.length < min || b.length > max) throw new IOException("invalid " + name); return b; }
        catch (IllegalArgumentException | NullPointerException e) { throw new IOException("invalid " + name, e); }
    }
    private static int requiredInt(JsonObject o,String n) { return o.get(n).getAsInt(); }
    private static long requiredLong(JsonObject o,String n) { return o.get(n).getAsLong(); }
    @Override public void close() { writer.shutdown(); }
}
