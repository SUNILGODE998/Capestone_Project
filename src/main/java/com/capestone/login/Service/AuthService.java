package com.capestone.login.Service;

import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
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

    private final AuthenticationManager authenticationManager; // @Lazy to break cycle
    private final JwtUtil jwtUtil;
    private final Set<String> tokenBlacklist = new HashSet<>();

    public AuthService(@Lazy AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @CircuitBreaker(name = "authServiceCircuitBreaker", fallbackMethod = "fallbackLogin")
    public String login(String username, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            return jwtUtil.generateToken(auth);

        } catch (BadCredentialsException ex) {
            // Counted as invalid credentials → throw 500
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Invalid username or password");

        } catch (Exception ex) {
            // Counted by CircuitBreaker → fallback will return 503
            throw new RuntimeException("Authentication service failure", ex);
        }
    }

    public String fallbackLogin(String username, String password, Throwable t) {
        logger.error("CircuitBreaker OPEN. Login temporarily disabled for user: {}", username, t);
        throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Too many failed login attempts. Please try again later.");
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
