package com.seq.acheron.vault.storables;

import com.google.gson.JsonObject;
import com.seq.acheron.vault.interfaces.Storable;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Central registry of {@link Storable} types known to AcheronCore, keyed by
 * their {@linkplain Storable#category() persistence category}.
 * <p>
 * This is the single place that needs to change to support a new storable
 * type end to end: register it here and {@code VaultFactory.fromJson} picks
 * it up automatically, no parallel {@code if (root.has(...))} branch needed.
 * Adding a type still requires writing the storable class itself (with its
 * {@code CATEGORY} constant and {@code fromJson} factory method) — only the
 * dispatch wiring is centralised.
 */
public final class StorableTypes {

    /** Builds a {@link Storable} of a known type from its JSON representation. */
    public interface JsonFactory {
        Storable fromJson(JsonObject json);
    }

    private static final Map<String, JsonFactory> REGISTRY = new LinkedHashMap<>();

    static {
        register(Account.CATEGORY, Account::fromJson);
        register(CreditCard.CATEGORY, CreditCard::fromJson);
        register(SecureNote.CATEGORY, SecureNote::fromJson);
        register(Identity.CATEGORY, Identity::fromJson);
        register(BankAccount.CATEGORY, BankAccount::fromJson);
        register(WifiNetwork.CATEGORY, WifiNetwork::fromJson);
        register(SoftwareLicense.CATEGORY, SoftwareLicense::fromJson);
    }

    private StorableTypes() {}

    private static void register(String category, JsonFactory factory) {
        REGISTRY.put(category, factory);
    }

    /**
     * @return all registered persistence categories, in registration order
     */
    public static Collection<String> categories() {
        return REGISTRY.keySet();
    }

    /**
     * Builds the {@link Storable} registered under {@code category} from its JSON form.
     *
     * @param category the persistence category, e.g. {@code "accounts"}
     * @param json     the entry's JSON representation
     * @return the reconstructed storable
     * @throws IllegalArgumentException if {@code category} is not registered
     */
    public static Storable fromJson(String category, JsonObject json) {
        JsonFactory factory = REGISTRY.get(category);
        if (factory == null) {
            throw new IllegalArgumentException("Unknown storable category: " + category);
        }
        return factory.fromJson(json);
    }
}
