package com.capestone.login.Controller;


import com.capestone.login.Model.User;
import com.capestone.login.Service.AuthService;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
//    @RateLimiter(name = "authServiceRateLimiter", fallbackMethod = "rateLimitFallback")
    public ResponseEntity<String> login(@RequestBody User user) {
        String token = authService.loginWithResilience(user.getUsername(), user.getPassword());
        return ResponseEntity.ok(token);
    }

    // ✅ RateLimiter fallback → 429
    public ResponseEntity<String> rateLimitFallback(@RequestBody User user, Throwable t) {
        logger.warn("Rate limit exceeded for user: {}", user.getUsername());
        throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                "Too many login attempts. Please wait before retrying.");
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String token) {
        try {
            if (token == null || !token.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            token = token.substring(7);

            // Validate token before logout
            if (authService.isTokenBlacklisted(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            authService.logout(token);
            return ResponseEntity.ok().build();

        } catch (ResponseStatusException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @ExceptionHandler(org.springframework.security.authentication.BadCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Map<String, String> handleBadCredentials(org.springframework.security.authentication.BadCredentialsException ex) {
        Map<String, String> error = new HashMap<>();
        error.put("message", "Invalid username or password");
        return error;
    }
}

