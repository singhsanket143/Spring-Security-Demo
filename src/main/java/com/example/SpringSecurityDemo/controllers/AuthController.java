package com.example.SpringSecurityDemo.controllers;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.SpringSecurityDemo.configs.security.JwtUtil;
import com.example.SpringSecurityDemo.dtos.LoginUserDTO;
import com.example.SpringSecurityDemo.dtos.RegisterUserDTO;
import com.example.SpringSecurityDemo.entities.Role;
import com.example.SpringSecurityDemo.entities.User;
import com.example.SpringSecurityDemo.services.RegisterUserService;
import com.example.SpringSecurityDemo.services.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final UserService userService;
    private final RegisterUserService registerUserService;

    private final JwtUtil jwtUtil;

    private final AuthenticationManager authenticationManager;


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterUserDTO registerUserDTO) {
        User user = registerUserService.registerUser(registerUserDTO.getEmail(), registerUserDTO.getPassword());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUserDTO loginUserDTO) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginUserDTO.getEmail(), loginUserDTO.getPassword())
        );

        UserDetails userDetails = userService.loadUserByUsername(loginUserDTO.getEmail());

        Set<Role> roles = userDetails.getAuthorities().stream().map(auth -> Role.valueOf(auth.getAuthority())).collect(Collectors.toSet());

        String token = jwtUtil.generateToken(
            userDetails.getUsername(),
            roles);

        return ResponseEntity.ok(token);

    }
}
