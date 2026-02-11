package com.seq.acheron.vault;

public class Password implements Storable{
    private String domain;
    private String user;
    private String password;

    @Override
    public String toJSON() {
        return "";
    }
}
