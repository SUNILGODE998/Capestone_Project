package com.capestone.login;

import com.capestone.login.Service.AuthService;
import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceTests {

    // Stub for AuthenticationManager
    static class AuthenticationManagerStub implements AuthenticationManager {
        private boolean valid = true;
        private boolean throwBadCredentials = false;
        private boolean throwRuntime = false;

        public void setValid(boolean valid) { this.valid = valid; }
        public void setThrowBadCredentials(boolean v) { this.throwBadCredentials = v; }
        public void setThrowRuntime(boolean v) { this.throwRuntime = v; }

        @Override
        public Authentication authenticate(Authentication authentication) {
            if (throwBadCredentials) throw new BadCredentialsException("Bad credentials");
            if (throwRuntime) throw new RuntimeException("DB down");
            if (valid) return authentication;
            throw new BadCredentialsException("Invalid");
        }
    }

    // Stub for JwtUtil
    static class JwtUtilStub extends JwtUtil {
        @Override
        public String generateToken(Authentication authentication) {
            return "fake-jwt-token";
        }
    }

    @Test
    void login_ShouldReturnToken_WhenCredentialsValid() {
        AuthenticationManagerStub authManager = new AuthenticationManagerStub();
        JwtUtilStub jwtUtil = new JwtUtilStub();
        CircuitBreakerRegistry circuitBreakerRegistry = CircuitBreakerRegistry.ofDefaults();
        RateLimiterRegistry rateLimiterRegistry = RateLimiterRegistry.ofDefaults();
        AuthService authService = new AuthService(authManager, jwtUtil, circuitBreakerRegistry, rateLimiterRegistry);

        String token = authService.login("user", "pass");
        assertEquals("fake-jwt-token", token);
    }

    @Test
    void login_ShouldThrow500_WhenInvalidCredentials() {
        AuthenticationManagerStub authManager = new AuthenticationManagerStub();
        authManager.setThrowBadCredentials(true);
        JwtUtilStub jwtUtil = new JwtUtilStub();
        CircuitBreakerRegistry circuitBreakerRegistry = CircuitBreakerRegistry.ofDefaults();
        RateLimiterRegistry rateLimiterRegistry = RateLimiterRegistry.ofDefaults();
        AuthService authService = new AuthService(authManager, jwtUtil, circuitBreakerRegistry, rateLimiterRegistry);

        BadCredentialsException exception = assertThrows(BadCredentialsException.class,
                () -> authService.login("wrong", "wrong"));

        assertEquals("Invalid username or password", exception.getMessage());
    }

    @Test
    void login_ShouldThrowRuntime_WhenServiceFailure() {
        AuthenticationManagerStub authManager = new AuthenticationManagerStub();
        authManager.setThrowRuntime(true);
        JwtUtilStub jwtUtil = new JwtUtilStub();
        CircuitBreakerRegistry circuitBreakerRegistry = CircuitBreakerRegistry.ofDefaults();
        RateLimiterRegistry rateLimiterRegistry = RateLimiterRegistry.ofDefaults();
        AuthService authService = new AuthService(authManager, jwtUtil, circuitBreakerRegistry, rateLimiterRegistry);

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> authService.login("user", "pass"));

        assertTrue(exception.getMessage().contains("Authentication service failure"));
    }
}