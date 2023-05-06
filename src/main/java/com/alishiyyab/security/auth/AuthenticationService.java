package com.alishiyyab.security.auth;

import com.alishiyyab.security.config.JwtService;
import com.alishiyyab.security.user.Role;
import com.alishiyyab.security.user.User;
import com.alishiyyab.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .dateOfBirth(request.getDateOfBirth())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .phoneNumber(request.getPhoneNumber())
                .role(Role.USER)
                .build();
        userRepository.save(user);
        return addClaims(user);
    }

    public AuthenticationResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        return addClaims(user);
    }

    private AuthenticationResponse addClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userEmail", user.getEmail());
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());
        claims.put("role", user.getRole());
        var jwtToken = jwtService.generateTokens(claims, user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
