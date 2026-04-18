package com.gmail.clarkin200.securitywebstarter.service;

import com.gmail.clarkin200.securitywebstarter.conf.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

public class JwtService {

    private final JwtProperties properties;
    private final SecretKey secretKey;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.secretKey = buildKey(properties);
    }

    private SecretKey buildKey(JwtProperties properties) {
        byte[] keyBytes;

        if (properties.isBase64()) {
            keyBytes = Base64.getDecoder().decode(properties.getSecret());
        } else {
            keyBytes = properties.getSecret().getBytes(StandardCharsets.UTF_8);
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractTokenFromHeader(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return null;
        }

        if (!headerValue.startsWith(properties.getPrefix())) {
            return null;
        }

        return headerValue.substring(properties.getPrefix().length());
    }

    public Claims extractAllClaims(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("JWT token is null or blank");
        }

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Claims extractAllClaimsFromHeader(String headerValue) {
        String token = extractTokenFromHeader(headerValue);

        if (token == null) {
            throw new IllegalArgumentException("Authorization header does not contain Bearer token");
        }

        return extractAllClaims(token);
    }

    public <T> T extractClaim(String token, Function<Claims, T> extractor) {
        Claims claims = extractAllClaims(token);
        return extractor.apply(claims);
    }

    public <T> T extractClaim(String token, String claimName, Class<T> requiredType) {
        Claims claims = extractAllClaims(token);
        return claims.get(claimName, requiredType);
    }

    public Map<String, Object> extractClaimsMap(String token) {
        return extractAllClaims(token);
    }

    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Long extractUserId(String token) {
        Object value = extractAllClaims(token).get("uid");

        if (value instanceof Integer) {
            return ((Integer) value).longValue();
        }

        if (value instanceof Long) {
            return (Long) value;
        }

        if (value instanceof String) {
            return Long.parseLong((String) value);
        }

        return null;
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Date expiration = claims.getExpiration();
            return expiration == null || expiration.after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
