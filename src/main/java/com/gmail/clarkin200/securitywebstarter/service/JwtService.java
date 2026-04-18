package com.gmail.clarkin200.securitywebstarter.service;

import com.gmail.clarkin200.securitywebstarter.security.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final SecretKey secretKey;
    private final JwtProperties properties;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.secretKey = Keys.hmacShaKeyFor(
                properties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    public String extractTokenFromHeader(String headerValue) {
        if (headerValue == null || !headerValue.startsWith(properties.getPrefix())) {
            return null;
        }
        return headerValue.substring(properties.getPrefix().length());
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
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

    public Long extractUserId(String token) {
        Object value = extractAllClaims(token).get("uid");

        if (value instanceof Integer i) return i.longValue();
        if (value instanceof Long l) return l;
        if (value instanceof String s) return Long.parseLong(s);

        throw new IllegalStateException("Claim uid is missing or invalid");
    }

    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractRole(String token) {
        Object role = extractAllClaims(token).get("role");
        return role == null ? null : role.toString();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Object roles = extractAllClaims(token).get("roles");

        if (roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }

        String role = extractRole(token);
        return role == null ? Collections.emptyList() : List.of(role);
    }

    public String generateAccessToken(
            Long userId,
            String email,
            List<String> roles,
            long expirationMs
    ) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(email)
                .claim("uid", userId)
                .claim("roles", roles)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }
}
