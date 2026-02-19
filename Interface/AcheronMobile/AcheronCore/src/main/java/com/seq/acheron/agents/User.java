package com.seq.acheron.agents;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

/**
 * Represents a registered user of the Acheron vault system.
 * <p>
 * A {@code User} is identified by a unique integer ID. Users are referenced
 * by {@link com.seq.acheron.vault.storables.VaultObject} instances as part of
 * their access-control list (ACL), which determines who is allowed to read or
 * share a given vault entry.
 * <p>
 * The natural ordering defined by {@link #compareTo} is ascending by {@link #id},
 * which makes {@code User} instances sortable and usable in ordered collections.
 *
 * @see com.seq.acheron.vault.storables.Sharable
 * @see com.seq.acheron.vault.storables.VaultObject
 */
public class User implements Comparable<User> {

    /**
     * The unique identifier for this user. Assigned at construction time
     * and immutable afterwards.
     */
    @Getter
    private final Integer id;

    /**
     * Creates a new {@code User} with the given unique identifier.
     *
     * @param id the user's unique identifier; must not be {@code null}
     * @throws IllegalArgumentException if {@code id} is {@code null}
     */
    public User(@NotNull Integer id) {
        this.id = id;
    }

    /**
     * Compares this user to another by ascending {@link #id}.
     *
     * @param other the other user; must not be {@code null}
     * @return a negative integer, zero, or positive integer if this user's id
     *         is less than, equal to, or greater than the other's
     */
    @Override
    public int compareTo(@NotNull User other) {
        return this.id.compareTo(other.id);
    }

    /**
     * Returns {@code true} if this user has the same {@link #id} as {@code obj}.
     * Consistent with {@link #compareTo}.
     *
     * @param obj the object to compare
     * @return {@code true} if both users share the same id
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof User)) return false;
        return this.id.equals(((User) obj).id);
    }

    /**
     * Returns a hash code based on the user's {@link #id}. Consistent
     * with {@link #equals}, ensuring correct behaviour in hash-based
     * collections such as {@link java.util.HashSet}.
     *
     * @return hash code of {@link #id}
     */
    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
