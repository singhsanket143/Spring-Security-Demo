package com.example.SpringSecurityDemo.services;

import java.util.Set;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.SpringSecurityDemo.entities.Role;
import com.example.SpringSecurityDemo.entities.User;
import com.example.SpringSecurityDemo.repositories.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RegisterUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public User registerUser(String email, String password) {
        if(userRepository.existsByEmail(email)) {
            throw new RuntimeException("User already exists");
        }

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setPassword(passwordEncoder.encode(password));

        newUser.setRoles(Set.of(Role.USER));

        return userRepository.save(newUser);
    }



    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
