package com.seq.acheron.util;

import com.seq.acheron.vault.storables.VaultObject;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * An immutable generic container holding a pair of two related values.
 * <p>
 * {@code Pair} is used throughout AcheronCore to associate two values without
 * needing a dedicated class. For example, {@link VaultObject#sliceCode()}
 * returns a {@code Pair<String, String>} where {@link #left} holds the type
 * prefix (e.g. {@code "ACC"}) and {@link #right} holds the sequential number
 * (e.g. {@code "0"}).
 * <p>
 * Both values are {@code public final} and set at construction time.
 * {@link #equals} and {@link #hashCode} are implemented so that this class
 * works correctly in hash-based collections and in comparisons like the one
 * performed by {@link VaultObject#compareTo}.
 *
 * @param <L>   the type of the left value
 * @param <R>   the type of the right value
 * @param left  The left element of the pair. May be {@code null}.
 * @param right The right element of the pair. May be {@code null}.
 */
public record Pair<L, R>(L left, R right) {

    /**
     * Creates a new immutable {@code Pair}.
     *
     * @param left  the left value (may be {@code null})
     * @param right the right value (may be {@code null})
     */
    public Pair {
    }

    /**
     * Returns {@code true} if both elements compare equal to those of the given
     * object, using {@link Objects#equals} for null-safe comparison.
     *
     * @param obj the object to compare against
     * @return {@code true} if {@code obj} is a {@code Pair} with equal
     * {@link #left} and {@link #right} values
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Pair<?, ?>(Object left1, Object right1))) return false;
        return Objects.equals(this.left, left1)
                && Objects.equals(this.right, right1);
    }

    /**
     * Returns a human-readable representation of this pair.
     *
     * @return {@code "(left, right)"}
     */
    @Override
    public @NotNull String toString() {
        return "(" + left + ", " + right + ")";
    }
}
