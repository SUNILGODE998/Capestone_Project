package com.capestone.login.Model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.NotBlank;

@Entity
@Table(name="users")
public class User {

    @Id
    @NotBlank(message = "Username cannot be blank")
    @Pattern(
            regexp = "^[^(){}]*@gmail\\.com$",
            message = "Username must end with @gmail.com and cannot contain () or {}"
    )
    private String username;

    @NotBlank(message = "Password cannot be blank")
    @Pattern(
            regexp = "^(?=.*[A-Z])(?=.*[^a-zA-Z0-9])[^(){}]+$",
            message = "Password must contain at least one uppercase letter, one special character, and cannot contain () or {}"
    )
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}