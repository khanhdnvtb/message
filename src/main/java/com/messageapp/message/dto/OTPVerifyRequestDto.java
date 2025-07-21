package com.messageapp.message.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class OTPVerifyRequestDto {
    @Email
    @NotBlank(message = "Email cannot be blank!")
    private String email;

    @NotBlank(message = "OTP cannot be blank!")
    @Size(min = 6, max = 6)
    private String otpCode;

    @NotBlank(message = "Password cannot be blank!")
    @Size(min = 6)
    private String password;
}
