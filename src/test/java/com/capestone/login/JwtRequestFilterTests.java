package com.capestone.login;

import com.capestone.login.Filter.JwtRequestFilter;
import com.capestone.login.Service.UserService;
import com.capestone.login.Util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.FilterChain;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtRequestFilterTests {

    private JwtRequestFilter jwtRequestFilter;
    private JwtUtil jwtUtil;
    private UserService userService;
    private HashSet<String> blacklist;

    @BeforeEach
    void setUp() {
        jwtUtil = Mockito.mock(JwtUtil.class);
        userService = Mockito.mock(UserService.class);
        blacklist = new HashSet<>();
        jwtRequestFilter = new JwtRequestFilter(userService, jwtUtil, blacklist);
    }

    @Test
    void testValidTokenPasses() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = Mockito.mock(FilterChain.class);

        Mockito.when(jwtUtil.extractUsername("valid-token")).thenReturn("john");
        Mockito.when(jwtUtil.validateToken(Mockito.anyString(), Mockito.any(UserDetails.class)))
                .thenReturn(true);
        Mockito.when(userService.loadUserByUsername("john"))
                .thenReturn(org.springframework.security.core.userdetails.User
                        .withUsername("john").password("pass").authorities("USER").build());

        jwtRequestFilter.doFilterInternal(request, response, chain);
        Mockito.verify(chain).doFilter(request, response);
    }

    @Test
    void testBlacklistedTokenThrowsUnauthorized() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer bad-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = Mockito.mock(FilterChain.class);

        blacklist.add("bad-token");

        assertThrows(ResponseStatusException.class,
                () -> jwtRequestFilter.doFilterInternal(request, response, chain));
    }
}
