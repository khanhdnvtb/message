package com.messageapp.message.service;

import com.messageapp.message.dto.RegisterRequestDto;
import com.messageapp.message.dto.AuthResponseDto;
import com.messageapp.message.dto.OTPVerifyRequestDto;
import com.messageapp.message.dto.LoginRequestDto;
import com.messageapp.message.dto.RefreshTokenRequestDto;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
    AuthResponseDto verifyOtpAndCreateSession(OTPVerifyRequestDto otpVerifyRequestDto, HttpServletRequest request);

    AuthResponseDto loginAndCreateSession(LoginRequestDto loginRequest, HttpServletRequest request);

    AuthResponseDto refreshToken(RefreshTokenRequestDto request);

    void logout(RefreshTokenRequestDto request);

    void sendOTP(RegisterRequestDto registerRequestDto);
}
