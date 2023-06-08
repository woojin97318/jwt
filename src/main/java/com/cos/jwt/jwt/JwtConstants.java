package com.cos.jwt.jwt;

public final class JwtConstants {

    private JwtConstants() {
        throw new UnsupportedOperationException("JwtConstants should not be instantiated");
    }

    public static final String SECRET = "전우진";

    public static final int EXPIRATION_TIME = 24 * 60 * 60 * 1000;

    public static final String TOKEN_PREFIX = "Bearer ";

    public static final String HEADER_STRING = "Authorization";
}
