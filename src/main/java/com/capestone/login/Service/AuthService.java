package com.capestone.login.Service;

import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final Set<String> tokenBlacklist = new HashSet<>();

    public AuthService(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }


    public String login(String username, String password) {
        logger.info("Attempting login for user: {}", username);
        try {
            Authentication auth = authenticateUser(username, password);
            String token = jwtUtil.generateToken(auth);
            logger.info("Login successful for user: {}", username);
            return token;
        } catch (Exception e) {
            return "Service Unavailable";
        }
    }

    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "fallbackLogin")
    private Authentication authenticateUser(String username, String password) {
        throw new RuntimeException("Database Unavailable");
//        Authentication auth = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(username, password)
//        );
//        return auth;
    }

    // ✅ Fallback method for circuit breaker
    public String fallbackLogin(String username, String password, Throwable t) {
        logger.error("Authentication service is unavailable. Fallback triggered for user: {}", username, t);
        return "Authentication service is unavailable, please try again later.";
    }

    public void logout(String token) {
        String cleanToken = token.replace("Bearer ", "");
        String jti = jwtUtil.extractJti(cleanToken);
        logger.info("Logging out token with jti: {}", jti);
        tokenBlacklist.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        String cleanToken = token.replace("Bearer ", "");
        String jti = jwtUtil.extractJti(cleanToken);
        return tokenBlacklist.contains(jti);
    }
}
