package com.capestone.login;

import com.capestone.login.Filter.JwtRequestFilter;
import com.capestone.login.Service.UserService;
import com.capestone.login.Util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.FilterChain;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class JwtRequestFilterTests {

    private JwtRequestFilter jwtRequestFilter;
    private JwtUtil jwtUtil;
    private UserService userService;
    private HashSet<String> blacklist;

    // Stub for JwtUtil
    static class JwtUtilStub extends JwtUtil {
        @Override
        public String extractUsername(String token) {
            if ("valid-token".equals(token)) return "john";
            if ("bad-token".equals(token)) return "john";
            return null;
        }

        @Override
        public Boolean validateToken(String token, UserDetails userDetails) {
            return "valid-token".equals(token);
        }
    }

    // Stub for UserService
    static class UserServiceStub extends UserService {
        public UserServiceStub() {
            super(null); // Pass null since we don't use repository in stub
        }

        @Override
        public UserDetails loadUserByUsername(String username) {
            if ("john".equals(username)) {
                return org.springframework.security.core.userdetails.User
                        .withUsername("john").password("pass").authorities("USER").build();
            }
            throw new RuntimeException("User not found");
        }
    }

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtilStub();
        userService = new UserServiceStub();
        blacklist = new HashSet<>();
        jwtRequestFilter = new JwtRequestFilter(userService, jwtUtil, blacklist);
    }

    @Test
    void testValidTokenPasses() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        jwtRequestFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void testBlacklistedTokenThrowsUnauthorized() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer bad-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        blacklist.add("bad-token");

        assertThrows(ResponseStatusException.class,
                () -> jwtRequestFilter.doFilterInternal(request, response, chain));
    }
}