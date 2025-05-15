package com.example.authservice.controller;

import com.example.authservice.dto.AuthenticationRequest;
import com.example.authservice.dto.JwtAuthenticationResponse;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Аутентификация")
public class AuthenticationController {
    private final AuthService authService;

    @Operation(summary = "Регистрация пользователя")
    @PostMapping("/register")
    public ResponseEntity<JwtAuthenticationResponse> register(@RequestBody @Valid RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @Operation(summary = "Авторизация пользователя")
    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> login(@RequestBody @Valid AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
