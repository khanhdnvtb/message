package com.messageapp.message.service.impl;

import com.messageapp.message.dto.*;
import com.messageapp.message.entity.RefreshToken;
import com.messageapp.message.entity.User;
import com.messageapp.message.repository.RefreshTokenRepository;
import com.messageapp.message.repository.UserRepository;
import com.messageapp.message.security.JwtUtil;
import com.messageapp.message.service.AuthService;
import com.messageapp.message.service.OTPService;
import com.messageapp.message.service.RefreshTokenService;
import com.messageapp.message.session.UserSession;
import com.messageapp.message.session.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final OTPService otpService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final UserSessionService userSessionService;

    @Override
    @Transactional
    public AuthResponseDto verifyOtpAndCreateSession(OTPVerifyRequestDto otpVerifyRequestDto, HttpServletRequest request) {
        User user = otpService.verifyOtpAndCreateUser(otpVerifyRequestDto);
        refreshTokenRepository.deleteByUser(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        String ipAddress = request.getRemoteAddr();
        String deviceId = request.getHeader("Device-Id");
        String sessionId = userSessionService.saveSession(user, ipAddress, deviceId, refreshToken.getToken());
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), sessionId);
        return new AuthResponseDto(accessToken, refreshToken.getToken());
    }

    @Override
    @Transactional
    public AuthResponseDto loginAndCreateSession(LoginRequestDto loginRequest, HttpServletRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        refreshTokenRepository.deleteByUser(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        String ipAddress = request.getRemoteAddr();
        String deviceId = request.getHeader("Device-Id");
        String sessionId = userSessionService.saveSession(user, ipAddress, deviceId, refreshToken.getToken());
        String accessToken = jwtUtil.generateAccessToken(userDetails.getUsername(), sessionId);
        return new AuthResponseDto(accessToken, refreshToken.getToken());
    }

    @Override
    @Transactional
    public AuthResponseDto refreshToken(RefreshTokenRequestDto request) {
        String requestRefreshToken = request.getRefreshToken();
        RefreshToken oldToken = refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RuntimeException("Refresh token not found or expired!"));

        User user = oldToken.getUser();
        UserSession session = userSessionService.getSessionByUserId(user.getId())
                .orElseThrow(() -> new RuntimeException("Session not found. Please login again."));

        if (!session.getRefreshToken().equals(oldToken.getToken())) {
            userSessionService.removeSessionByUserId(user.getId());
            refreshTokenRepository.deleteByUser(user);
            throw new RuntimeException("Refresh token mismatch. Session terminated for security reasons.");
        }

        refreshTokenRepository.deleteByUser(user);
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);
        userSessionService.updateRefreshTokenInSession(user.getId(), newRefreshToken.getToken());
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), session.getSessionId());
        return new AuthResponseDto(accessToken, newRefreshToken.getToken());
    }

    @Override
    @Transactional
    public void logout(RefreshTokenRequestDto request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Refresh token not found!"));
        userSessionService.removeSessionByUserId(refreshToken.getUser().getId());
        refreshTokenService.revokeRefreshToken(refreshToken);
    }

    @Override
    public void sendOTP(RegisterRequestDto registerRequestDto) {
        otpService.sendOTP(registerRequestDto);
    }
}
