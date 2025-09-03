package com.capestone.login.Config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration

public class WebSecurityConfig implements WebMvcConfigurer {

    @Override

    public void addCorsMappings(CorsRegistry registry) {

        registry.addMapping("/**") // apply to all endpoints

                .allowedOrigins(

                        "http://localhost:5173",  // React dev server

                        "http://localhost:4200"   // Angular dev server

                )

                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")

                .allowedHeaders("*")

                .allowCredentials(true);
    }
}

