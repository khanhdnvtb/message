package com.messageapp.message.controller;

import com.messageapp.message.dto.AuthResponseDto;
import com.messageapp.message.dto.OTPVerifyRequestDto;
import com.messageapp.message.dto.RefreshTokenRequestDto;
import com.messageapp.message.dto.RegisterRequestDto;
import com.messageapp.message.dto.LoginRequestDto;
import com.messageapp.message.entity.RefreshToken;
import com.messageapp.message.entity.User;
import com.messageapp.message.repository.UserRepository;
import com.messageapp.message.repository.RefreshTokenRepository;
import com.messageapp.message.security.JwtUtil;
import com.messageapp.message.service.AuthService;
import com.messageapp.message.service.RefreshTokenService;
import com.messageapp.message.service.OTPService;
import com.messageapp.message.session.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/send-otp")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequestDto registerRequestDto) {
        authService.sendOTP(registerRequestDto);
        return ResponseEntity.ok("OTP sent to email successfully!");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponseDto> verify(@RequestBody @Valid OTPVerifyRequestDto otpVerifyRequestDto, HttpServletRequest request) {
        return ResponseEntity.ok(authService.verifyOtpAndCreateSession(otpVerifyRequestDto, request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody @Valid LoginRequestDto loginRequest, HttpServletRequest request) {
        return ResponseEntity.ok(authService.loginAndCreateSession(loginRequest, request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponseDto> refreshToken(@RequestBody RefreshTokenRequestDto request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshTokenRequestDto request) {
        authService.logout(request);
        return ResponseEntity.ok("Logged out successfully!");
    }
}
