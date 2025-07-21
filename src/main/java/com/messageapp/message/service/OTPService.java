package com.messageapp.message.service;

import com.messageapp.message.dto.OTPVerifyRequestDto;
import com.messageapp.message.dto.RegisterRequestDto;
import com.messageapp.message.entity.User;

public interface OTPService {
    void sendOTP(RegisterRequestDto registerRequestDto);

    void verifyOtp(OTPVerifyRequestDto otpVerifyRequestDto);

    int generateOtp(String userName);

    Boolean validateOtp(String otp, String key);

    User verifyOtpAndCreateUser(OTPVerifyRequestDto otpVerifyRequestDto);
}
