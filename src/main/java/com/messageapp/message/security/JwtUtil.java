package com.messageapp.message.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${app.jwt-secret}")
    private String jwtSecret;

    @Value("${app.jwt-access-expiration-ms:3600000}")
    private long jwtAccessExpirationMs;

    @Value("${app.jwt-refresh-expiration-ms:604800000}")
    private long jwtRefreshExpirationMs;

    public String generateAccessToken(String email, String sessionId) {
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + jwtAccessExpirationMs);
        return Jwts.builder()
                .subject(email)
                .issuedAt(currentDate)
                .expiration(expireDate)
                .claim("type", "access")
                .claim("sessionId", sessionId)
                .signWith(key())
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getEmailFromToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateToken(String token) {
        Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parse(token);
        return true;
    }

    public String getSessionIdFromToken(String token) {
        return (String) Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("sessionId");
    }
}