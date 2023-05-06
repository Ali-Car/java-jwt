package com.alishiyyab.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/")
@RequiredArgsConstructor
@CrossOrigin
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authenticationService.register(request));
    }


    @PostMapping("login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody LoginRequest request
    ) {
        return ResponseEntity.ok(authenticationService.login(request));
    }
}
