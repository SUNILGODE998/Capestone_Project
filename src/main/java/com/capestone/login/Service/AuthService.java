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

    // ✅ CircuitBreaker
    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "fallbackLogin")
    public String login(String username, String password) {
        try {

            logger.info("Login attempt for user: {}", username);

            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            String token = jwtUtil.generateToken(auth);
            logger.info("User '{}' logged in successfully. JWT issued.", username);
            return token;


        } catch (BadCredentialsException ex) {
            logger.warn("Invalid login attempt for user: {}", username);
            throw new BadCredentialsException("Invalid username or password");
        } catch (Exception ex) {
            logger.error("Unexpected authentication error for user '{}'", username, ex);
            throw new RuntimeException("Authentication service failure", ex);
        }
    }

    // ✅ CircuitBreaker fallback → 503
    public String fallbackLogin(String username, String password, Throwable t) {
        if (t instanceof BadCredentialsException ex) {
            throw ex; // propagate directly, skip fallback
        }

        logger.error("CircuitBreaker OPEN. Login temporarily disabled for user: {}", username);

        throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Server is unavailable! Please try after 30 seconds.");
    }

    public void logout(String token) {
        String cleanToken = token.replace("Bearer ", "");
        String jti = jwtUtil.extractJti(cleanToken);
        logger.info("Logging out token with jti: {}", jti);

        tokenBlacklist.add(jti);

        logger.info("Token with jti '{}' has been blacklisted successfully.", jti);
        logger.debug("Current blacklisted tokens: {}", tokenBlacklist);
    }

    public boolean isTokenBlacklisted(String token) {
        String cleanToken = token.replace("Bearer ", "");
        String jti = jwtUtil.extractJti(cleanToken);
        boolean blacklisted = tokenBlacklist.contains(jti);
        logger.debug("Token with jti '{}' blacklisted check: {}", jti, blacklisted);
        return blacklisted;
    }

    public Set<String> getTokenBlacklist() {
        return tokenBlacklist;
    }
}