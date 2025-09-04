package com.capestone.login.Service;

import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.function.Supplier;

@Service
public class AuthService {

    private final CircuitBreaker circuitBreaker;
    private final RateLimiter rateLimiter;
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager; // @Lazy avoids circular dependency
    private final JwtUtil jwtUtil;
    private final Set<String> tokenBlacklist = new HashSet<>();

    @Autowired
    public AuthService(
            @Lazy AuthenticationManager authenticationManager,
            JwtUtil jwtUtil,
            CircuitBreakerRegistry circuitBreakerRegistry,
            RateLimiterRegistry rateLimiterRegistry
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.circuitBreaker = circuitBreakerRegistry.circuitBreaker("authServiceCircuitBreaker");
        this.rateLimiter = rateLimiterRegistry.rateLimiter("authServiceRateLimiter");
    }

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

    public String loginWithResilience(String username, String password) {
        Supplier<String> loginSupplier = () -> login(username, password);
        Supplier<String> rateLimited = RateLimiter.decorateSupplier(rateLimiter, loginSupplier);
        Supplier<String> circuitBroken = CircuitBreaker.decorateSupplier(circuitBreaker, rateLimited);

        try {
            return circuitBroken.get();
        } catch (RequestNotPermitted ex) {
            logger.warn("Rate limit exceeded for user: {}", username);
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Too many login attempts. Please wait before retrying.");
        } catch (CallNotPermittedException ex) {
            logger.error("CircuitBreaker OPEN. Login temporarily disabled for user: {}", username);
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Server is unavailable! Please try after 30 seconds.");
        } catch (BadCredentialsException ex) {
            throw ex;
        } catch (Exception ex) {
            throw ex;
        }
    }
}