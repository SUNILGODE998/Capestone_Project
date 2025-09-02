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

    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "fallbackLogin")
    public String login(String username, String password) {
        logger.info("Attempting login for user: {}", username);

        // Simulate failure for testing
        if ("fail".equals(username)) {
            throw new RuntimeException("Simulated failure");
        }

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        String token = jwtUtil.generateToken(auth);
        logger.info("Login successful for user: {}", username);
        return token;
    }

    // ✅ Fallback method for circuit breaker
    public String fallbackLogin(String username, String password, Throwable t) {
        if (t instanceof CallNotPermittedException) {
            logger.warn("Circuit breaker is OPEN. Login temporarily disabled for user: {}", username);
            return "Too many failed attempts. Please wait before trying again.";
        }

        logger.error("Login failed for user: {}. Fallback triggered due to: {}", username, t.getMessage());
        return "Login service is temporarily unavailable";
    }

    public void logout(String token) {
        logger.info("Logging out token: {}", token);
        tokenBlacklist.add(token);
    }

    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }
}
