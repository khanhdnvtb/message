package com.messageapp.message.controller;

import com.messageapp.message.dto.AuthResponseDto;
import com.messageapp.message.dto.OTPVerifyRequestDto;
import com.messageapp.message.dto.RefreshTokenRequestDto;
import com.messageapp.message.dto.RegisterRequestDto;
import com.messageapp.message.dto.LoginRequestDto;
import com.messageapp.message.entity.RefreshToken;
import com.messageapp.message.entity.User;
import com.messageapp.message.repository.UserRepository;
import com.messageapp.message.security.JwtUtil;
import com.messageapp.message.service.AuthService;
import com.messageapp.message.service.RefreshTokenService;
import com.messageapp.message.service.OTPService;
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
    private final OTPService otpService;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    @PostMapping("/send-otp")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequestDto registerRequestDto) {
        otpService.sendOTP(registerRequestDto);
        return ResponseEntity.ok("OTP sent to email successfully!");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponseDto> verify(@RequestBody @Valid OTPVerifyRequestDto otpVerifyRequestDto) {
        User user = otpService.verifyOtpAndCreateUser(otpVerifyRequestDto);
        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        String accessToken = jwtUtil.generateAccessToken(user.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        return ResponseEntity.ok(new AuthResponseDto(accessToken, refreshToken.getToken()));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponseDto> refreshToken(@RequestBody RefreshTokenRequestDto request) {
        String requestRefreshToken = request.getRefreshToken();
        RefreshToken refreshToken = refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RuntimeException("Refresh token not found!"));
        String accessToken = jwtUtil.generateAccessToken(refreshToken.getUser().getUsername());
        return ResponseEntity.ok(new AuthResponseDto(accessToken, requestRefreshToken));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody @Valid LoginRequestDto loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String accessToken = jwtUtil.generateAccessToken(userDetails.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        return ResponseEntity.ok(new AuthResponseDto(accessToken, refreshToken.getToken()));
    }
}
