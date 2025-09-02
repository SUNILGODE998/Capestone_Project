package com.capestone.login.Service;

import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager; // @Lazy avoids circular dependency
    private final JwtUtil jwtUtil;
    private final Set<String> tokenBlacklist = new HashSet<>();

    public AuthService(@Lazy AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    // ✅ CircuitBreaker + RateLimiter applied
    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "fallbackLogin")
    @RateLimiter(name = "authServiceRateLimiter", fallbackMethod = "rateLimitFallback")
    public String login(String username, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            return jwtUtil.generateToken(auth);

        } catch (BadCredentialsException ex) {
            // Counted as invalid credentials → returns 500
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Invalid username or password");

        } catch (Exception ex) {
            // Counted by CircuitBreaker → fallback returns 503
            throw new RuntimeException("Authentication service failure", ex);
        }
    }

    // ✅ RateLimiter fallback → 429
    public String rateLimitFallback(String username, String password, Throwable t) {
        throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                "Too many login attempts. Please wait before retrying.");
    }

    // ✅ CircuitBreaker fallback → 503
    public String fallbackLogin(String username, String password, Throwable t) {
        logger.error("CircuitBreaker OPEN. Login temporarily disabled for user: {}", username, t);
        throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Server is unavailable! Please try after 30 seconds.");
    }

    public void logout(String token) {
        String cleanToken = token.replace("Bearer ", "");
        String jti = jwtUtil.extractJti(cleanToken);
        logger.info("Logging out token with jti: {}", jti);
        tokenBlacklist.add(jti);
    }

    public boolean isTokenBlacklisted(String token) {
        String cleanToken = token.replace("Bearer ", "");
        String jti = jwtUtil.extractJti(cleanToken);
        return tokenBlacklist.contains(jti);
    }

    public Set<String> getTokenBlacklist() {
        return tokenBlacklist;
    }
}