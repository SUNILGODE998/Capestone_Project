package com.capestone.login;

import com.capestone.login.Model.User;
import com.capestone.login.Service.AuthService;
import com.capestone.login.Filter.JwtRequestFilter;
import com.capestone.login.Service.UserService;
import com.capestone.login.Util.JwtUtil;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTests {

    @Autowired
    private MockMvc mockMvc;

    private User validUser;

    @TestConfiguration
    static class TestConfig {
        @Bean
        AuthService authService() {
            AuthenticationManager dummyManager = new AuthenticationManager() {
                @Override
                public Authentication authenticate(Authentication authentication) {
                    return authentication;
                }
            };
            JwtUtil dummyJwtUtil = new JwtUtil() {
            };
            CircuitBreakerRegistry dummyCircuitBreakerRegistry = CircuitBreakerRegistry.ofDefaults();
            RateLimiterRegistry dummyRateLimiterRegistry = RateLimiterRegistry.ofDefaults();

            return new AuthService(
                    dummyManager,
                    dummyJwtUtil,
                    dummyCircuitBreakerRegistry,
                    dummyRateLimiterRegistry
            ) {
                @Override
                public String login(String username, String password) {
                    if ("john".equals(username) && "password".equals(password)) {
                        return "mock-jwt-token";
                    }
                    throw new BadCredentialsException("Invalid credentials");
                }

                @Override
                public void logout(String token) {
                    // Do nothing for valid token
                }

                @Override
                public boolean isTokenBlacklisted(String token) {
                    return "invalid-token".equals(token);
                }
            };
        }
        @Bean
        JwtRequestFilter jwtRequestFilter(UserService userService, JwtUtil jwtUtil) {
            return new JwtRequestFilter(userService, jwtUtil, new java.util.HashSet<>());
        }

        @Bean
        JwtUtil jwtUtil() {
            return new JwtUtil() {};
        }
    }

    @BeforeEach
    void setUp() {
        validUser = new User();
        validUser.setUsername("john");
        validUser.setPassword("password");
    }

    @Test
    void testLoginSuccess() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"john\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string("mock-jwt-token"));
    }

    @Test
    void testLoginBadCredentials() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"john\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    @Test
    void testLogoutSuccess() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk());
    }

    @Test
    void testLogoutInvalidToken() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }
}