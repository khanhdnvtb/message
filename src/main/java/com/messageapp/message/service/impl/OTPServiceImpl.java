package com.messageapp.message.service.impl;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.messageapp.message.dto.OTPVerifyRequestDto;
import com.messageapp.message.dto.RegisterRequestDto;
import com.messageapp.message.entity.User;
import com.messageapp.message.repository.UserRepository;
import com.messageapp.message.service.OTPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.http.HttpStatus;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;


import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class OTPServiceImpl implements OTPService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    public JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    private static final Integer EXPIRE_MINS = 5;

    private LoadingCache<String, Integer> otpCache;

    public OTPServiceImpl() {
        super();
        otpCache = CacheBuilder.newBuilder().expireAfterWrite(EXPIRE_MINS, TimeUnit.MINUTES)
                .build(new CacheLoader<String, Integer>() {
                    public Integer load(String key) {
                        return 0;
                    }
                });
    }

    @Transactional
    @Override
    public void sendOTP(RegisterRequestDto registerRequestDto) {
        if (userRepository.findByEmail(registerRequestDto.getEmail()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email has been registered!");
        }
        int otp = generateOtp(registerRequestDto.getEmail());

        sendOTPCode(registerRequestDto.getEmail(), otp);
    }

    @Override
    public void verifyOtp(OTPVerifyRequestDto otpVerifyRequestDto) {
        verifyOtpAndCreateUser(otpVerifyRequestDto);
    }

    public void sendOTPCode(String emailTo, Integer otpCode) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(fromEmail);
        msg.setTo(emailTo);
        msg.setSubject("OTP code to authenticate registration");
        msg.setText("Your OTP code is: " + otpCode + "\nExpires in 5 minutes.");
        try {
            javaMailSender.send(msg);
        } catch (MailException e) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    e.getMessage()
            );
        }
    }

    public int getOtp(String key) {
        try {
            return otpCache.get(key);
        } catch (Exception e) {
            return 0;
        }
    }

    public void clearOTP(String key) {
        otpCache.invalidate(key);
    }

    @Override
    public int generateOtp(String key) {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        otpCache.put(key, otp);
        return otp;
    }

    @Override
    public Boolean validateOtp(String otp, String key) {
        int serverOtp = getOtp(key);
        if (serverOtp > 0) {
            if (serverOtp == Integer.parseInt(otp)) {
                clearOTP(key);
                return true;
            }
        }
        return false;
    }

    @Override
    public User verifyOtpAndCreateUser(OTPVerifyRequestDto otpVerifyRequestDto) {
        boolean isValid = false;
        if (isOTPValid(otpVerifyRequestDto.getOtpCode())) {
            isValid = validateOtp(otpVerifyRequestDto.getOtpCode(), otpVerifyRequestDto.getEmail());
        }
        if (!isValid) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "OTP code is invalid!");
        }
        if (userRepository.findByEmail(otpVerifyRequestDto.getEmail()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists!");
        }
        User newUser = User.builder()
                .email(otpVerifyRequestDto.getEmail())
                .password(passwordEncoder.encode(otpVerifyRequestDto.getPassword()))
                .build();
        userRepository.save(newUser);
        return newUser;
    }

    private Boolean isOTPValid(String otp) {
        try {
            Integer.parseInt(otp);
        } catch (NumberFormatException ex) {
            return false;
        }
        return true;
    }
}
