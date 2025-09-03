package com.capestone.login;

import com.capestone.login.Service.AuthService;
import com.capestone.login.Util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTests {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    @Test
    void login_ShouldReturnToken_WhenCredentialsValid() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(org.springframework.security.core.Authentication.class));
        when(jwtUtil.generateToken(any())).thenReturn("fake-jwt-token");

        // Act
        String token = authService.login("user", "pass");

        // Assert
        assertEquals("fake-jwt-token", token);
        verify(jwtUtil, times(1)).generateToken(any());
    }

    @Test
    void login_ShouldThrow500_WhenInvalidCredentials() {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> authService.login("wrong", "wrong"));

        assertEquals(500, exception.getStatusCode().value()); // In your code → 500
    }

    @Test
    void login_ShouldThrowRuntime_WhenServiceFailure() {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new RuntimeException("DB down"));

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> authService.login("user", "pass"));

        assertTrue(exception.getMessage().contains("Authentication service failure"));
    }
}
