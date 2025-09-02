package com.capestone.login.Util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {
    private final String SECRET_STRING = "qS5hGz4Jt2p9xR7wYv8u/A+b0cI1dE2f3gH4jK5lM6nO7p8qR9sT0u1vW2xY3z4A5B6C7D8E9F=\n";
    private final Key SECRET_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_STRING));
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);}

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);}

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);}

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY)
                .build().parseClaimsJws(token).getBody();}

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());}

    public String generateToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, authentication.getName());}

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();}

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}