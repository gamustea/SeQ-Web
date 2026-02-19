package com.seq.acheron.agents;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;

public class User implements Comparable<User> {
    @Getter
    private Integer id;

    @Override
    public int compareTo(@NotNull User other) {
        return this.id.compareTo(other.id);
    }
}
