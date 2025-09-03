package com.capestone.login.Util;

import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Component
public class JwtUtil {
    private final Key SECRET_KEY;
    public JwtUtil() {
        Dotenv dotenv = Dotenv.configure().load();
        String base64Key = dotenv.get("JWT_SECRET");
        if (base64Key == null) {
            throw new IllegalStateException("JWT_SECRET environment variable not set");
        }
        this.SECRET_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Key));
    }
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);}

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);}

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);}

   private Claims extractAllClaims(String token) {
                    return Jwts.parser()
                            .verifyWith((SecretKey) SECRET_KEY)
                            .build()
                            .parseSignedClaims(token)
                            .getPayload();
                }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());}

    public String generateToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, authentication.getName());}

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 30000)) // 10 hours
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();}

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }
}