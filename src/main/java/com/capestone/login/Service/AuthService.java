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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
public class AuthService {

    private static final int MAX_TOKEN_ATTEMPTS = 3;
    private static final long COOLDOWN_PERIOD_MS = 10000; // 1 minute

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final Set<String> tokenBlacklist = new HashSet<>();

    private final Map<String, Integer> tokenAttempts = new HashMap<>();
    private final Map<String, Long> cooldownStartTime = new HashMap<>();


    public AuthService(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "fallbackLogin")
    public String login(String username, String password) {
        logger.info("Attempting login for user: {}", username);

        long currentTime = System.currentTimeMillis();

        // Check if user is in cooldown
        if (cooldownStartTime.containsKey(username)) {
            long cooldownStart = cooldownStartTime.get(username);
            if (currentTime - cooldownStart < COOLDOWN_PERIOD_MS) {
                logger.warn("User {} is in cooldown period.", username);
                throw new RuntimeException("Too many requests. Please wait before generating another token.");
            } else {
                // Cooldown expired, reset counters
                cooldownStartTime.remove(username);
                tokenAttempts.put(username, 0);
            }
        }

        int attempts = tokenAttempts.getOrDefault(username, 0);
        if (attempts >= MAX_TOKEN_ATTEMPTS) {
            cooldownStartTime.put(username, currentTime);
            logger.warn("User {} exceeded token generation limit. Cooldown started.", username);
            throw new RuntimeException("Too many requests. Please wait before generating another token.");
        }


        // Simulate failure for testing
        if ("fail".equals(username)) {
            throw new RuntimeException("Simulated failure");
        }

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        String token = jwtUtil.generateToken(auth);

        tokenAttempts.put(username, attempts + 1);
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
