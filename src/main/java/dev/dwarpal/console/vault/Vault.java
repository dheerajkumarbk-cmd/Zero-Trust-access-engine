package dev.dwarpal.console.vault;

import dev.dwarpal.console.ConsoleAuth;
import dev.dwarpal.directory.CredentialLifecycle;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * What the vault keeps, and the rules for it. Two kinds of entry, both sealed on disk by {@link VaultStore}:
 * <ul>
 *   <li>each person's <b>emergency password</b>: made when the person is made, switched OFF, and of no use until an
 *       administrator switches it on. It opens one thing only: the recovery, where the person must then set a new password
 *       and a new PIN. Using it up replaces it with a new, switched-off one. If an administrator types a password of their
 *       own choosing it is kept as typed and stays readable in the vault until it is used;</li>
 *   <li>an administrator's <b>own</b> password and PIN, which only that administrator can read.</li>
 * </ul>
 * This class decides nothing about who may ask: the module does that, with the passkey, the elevation and the audit trail.
 */
public final class Vault implements CredentialLifecycle, ConsoleAuth.Emergency {

    public enum State { OFF, ACTIVE }

    /** A person's emergency password and where it stands. {@code activatedBy} and {@code activatedAt} are empty while OFF. */
    public record Credential(String person, String password, State state, boolean typed, Instant changedAt, String activatedBy,
                             Instant activatedAt) {
    }

    /** An administrator's own password and PIN. */
    public record Own(String password, String pin, Instant savedAt) {
    }

    public static final int MIN_TYPED = 10;
    public static final int MAX_TYPED = 64;
    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    private final VaultStore store;
    private final Clock clock;
    private final Object lock = new Object();
    private final SecureRandom random = new SecureRandom();
    private Map<String, Credential> emergency = new LinkedHashMap<>();
    private Map<String, Own> own = new LinkedHashMap<>();
    private volatile Consumer<String> usedListener = person -> {
    };

    private Vault(VaultStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** Opens the vault (data in one folder, its key in another); a vault that does not open with its key stops the start. */
    public static Vault open(java.nio.file.Path dataDir, java.nio.file.Path keyDir, Clock clock) throws IOException {
        Vault v = new Vault(VaultStore.open(dataDir, keyDir), clock);
        synchronized (v.lock) {
            v.load(v.store.read());
        }
        return v;
    }

    /** Who is told when an emergency password has been used (the module posts the notices and the record). */
    public void onUsed(Consumer<String> listener) {
        this.usedListener = listener;
    }

    // ---- the lifecycle of people -------------------------------------------------------------------------------------

    /** Every person in the list who has no emergency password yet gets a switched-off one. */
    public void ensure(Collection<String> people) {
        synchronized (lock) {
            commit(() -> people.forEach(p -> emergency.computeIfAbsent(p, this::fresh)));
        }
    }

    @Override
    public void personCreated(String personId) {
        ensure(List.of(personId));
    }

    @Override
    public void personRemoved(String personId) {
        synchronized (lock) {
            commit(() -> {
                emergency.remove(personId);
                own.remove(personId);
            });
        }
    }

    // ---- emergency passwords -----------------------------------------------------------------------------------------

    public Credential credential(String person) {
        synchronized (lock) {
            ensure(List.of(person));
            return emergency.get(person);
        }
    }

    public List<Credential> all() {
        synchronized (lock) {
            return new ArrayList<>(emergency.values());
        }
    }

    /** Switches the person's emergency password on, on behalf of this administrator. */
    public Credential activate(String person, String by) {
        synchronized (lock) {
            ensure(List.of(person));
            Credential c = emergency.get(person);
            Credential on = new Credential(person, c.password(), State.ACTIVE, c.typed(), c.changedAt(), by, clock.instant());
            commit(() -> emergency.put(person, on));
            return on;
        }
    }

    public Credential switchOff(String person) {
        synchronized (lock) {
            ensure(List.of(person));
            Credential c = emergency.get(person);
            Credential off = new Credential(person, c.password(), State.OFF, c.typed(), c.changedAt(), "", null);
            commit(() -> emergency.put(person, off));
            return off;
        }
    }

    /** An administrator's own choice of emergency password, kept as typed (and readable in the vault). State does not change. */
    public Credential setTyped(String person, String password) {
        synchronized (lock) {
            if (!typedOk(password)) {
                throw new IllegalArgumentException("a chosen emergency password is " + MIN_TYPED + " to " + MAX_TYPED + " printable characters");
            }
            ensure(List.of(person));
            Credential c = emergency.get(person);
            Credential next = new Credential(person, password, c.state(), true, clock.instant(), c.activatedBy(), c.activatedAt());
            commit(() -> emergency.put(person, next));
            return next;
        }
    }

    /** True while the person's emergency password is switched on and this is it. */
    @Override
    public boolean accepts(String user, String code) {
        synchronized (lock) {
            Credential c = emergency.get(user);
            return c != null && code != null && c.state() == State.ACTIVE && MessageDigest.isEqual(
                    c.password().getBytes(StandardCharsets.UTF_8), code.strip().getBytes(StandardCharsets.UTF_8));
        }
    }

    /** The person set new secrets with it: it is replaced by a new random one, switched off. */
    @Override
    public void used(String user) {
        synchronized (lock) {
            commit(() -> emergency.put(user, fresh(user)));
        }
        usedListener.accept(user);
    }

    // ---- an administrator's own entry --------------------------------------------------------------------------------

    public Optional<Own> own(String admin) {
        synchronized (lock) {
            return Optional.ofNullable(own.get(admin));
        }
    }

    public void saveOwn(String admin, String password, String pin) {
        synchronized (lock) {
            Own o = new Own(password, pin, clock.instant());
            commit(() -> own.put(admin, o));
        }
    }

    // ---- inside ------------------------------------------------------------------------------------------------------

    private Credential fresh(String person) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            if (i > 0 && i % 4 == 0) {
                sb.append('-');
            }
            sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
        }
        return new Credential(person, sb.toString(), State.OFF, false, clock.instant(), "", null);
    }

    private static boolean typedOk(String p) {
        if (p == null || p.length() < MIN_TYPED || p.length() > MAX_TYPED) {
            return false;
        }
        for (int i = 0; i < p.length(); i++) {
            if (Character.isISOControl(p.charAt(i))) {
                return false;
            }
        }
        return p.equals(p.strip());
    }

    /** Applies a change, saves it, and puts everything back as it was if the save fails. */
    private void commit(Runnable change) {
        Map<String, Credential> beforeEmergency = new LinkedHashMap<>(emergency);
        Map<String, Own> beforeOwn = new LinkedHashMap<>(own);
        change.run();
        if (beforeEmergency.equals(emergency) && beforeOwn.equals(own)) {
            return;
        }
        try {
            store.write(json());
        } catch (IOException ex) {
            emergency = beforeEmergency;
            own = beforeOwn;
            throw new IllegalStateException("the vault could not be saved", ex);
        }
    }

    private String json() {
        JsonValue.JObject.Builder emergencies = JsonValue.object();
        for (Credential c : emergency.values()) {
            emergencies.put(c.person(), JsonValue.object().put("password", c.password()).put("state", c.state().name())
                    .put("typed", JsonValue.bool(c.typed())).put("changedAt", c.changedAt().toString())
                    .put("activatedBy", c.activatedBy()).put("activatedAt", c.activatedAt() == null ? "" : c.activatedAt().toString())
                    .build());
        }
        JsonValue.JObject.Builder owns = JsonValue.object();
        for (Map.Entry<String, Own> x : own.entrySet()) {
            owns.put(x.getKey(), JsonValue.object().put("password", x.getValue().password()).put("pin", x.getValue().pin())
                    .put("savedAt", x.getValue().savedAt().toString()).build());
        }
        return JsonWriter.write(JsonValue.object().put("emergency", emergencies.build()).put("own", owns.build()).build());
    }

    private void load(String text) throws IOException {
        try {
            JsonValue.JObject root = (JsonValue.JObject) new JsonReader().read(text);
            if (root.get("emergency").orElse(null) instanceof JsonValue.JObject es) {
                for (String person : es.keys()) {
                    JsonValue.JObject c = (JsonValue.JObject) es.get(person).orElseThrow();
                    String at = text(c, "activatedAt");
                    emergency.put(person, new Credential(person, text(c, "password"), State.valueOf(text(c, "state")),
                            c.get("typed").orElseThrow().equals(JsonValue.bool(true)), Instant.parse(text(c, "changedAt")),
                            text(c, "activatedBy"), at.isEmpty() ? null : Instant.parse(at)));
                }
            }
            if (root.get("own").orElse(null) instanceof JsonValue.JObject os) {
                for (String admin : os.keys()) {
                    JsonValue.JObject o = (JsonValue.JObject) os.get(admin).orElseThrow();
                    own.put(admin, new Own(text(o, "password"), text(o, "pin"), Instant.parse(text(o, "savedAt"))));
                }
            }
        } catch (RuntimeException e) {
            throw new IOException("the vault opened but its content is not what this console wrote", e);
        }
    }

    private static String text(JsonValue.JObject o, String key) {
        return ((JsonValue.JString) o.get(key).orElseThrow()).value();
    }
}
