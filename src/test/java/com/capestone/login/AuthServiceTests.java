package com.capestone.login;

import com.capestone.login.Service.AuthService;
import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTests {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        CircuitBreakerRegistry cbRegistry = CircuitBreakerRegistry.ofDefaults();
        RateLimiterRegistry rlRegistry = RateLimiterRegistry.ofDefaults();
        authService = new AuthService(authenticationManager, jwtUtil, cbRegistry, rlRegistry);
    }

    @Test
    void login_ShouldReturnToken_WhenCredentialsValid() {
        // Arrange
        Authentication auth = new UsernamePasswordAuthenticationToken("user", "pass");

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(auth);

        doReturn("fake-jwt-token")
                .when(jwtUtil).generateToken(any(Authentication.class), anyString());

        // Act
        String token = authService.login("user", "pass");

        // Assert
        assertEquals("fake-jwt-token", token);
    }

    @Test
    void login_ShouldThrowException_WhenInvalidCredentials() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(BadCredentialsException.class,
                () -> authService.login("wrong", "wrong"));
    }
}
