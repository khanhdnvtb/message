package com.messageapp.message.service;

import com.messageapp.message.entity.RefreshToken;
import com.messageapp.message.entity.User;

import java.util.Optional;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(User user);
    Optional<RefreshToken> findByToken(String token);
    RefreshToken verifyExpiration(RefreshToken token);
    void revokeRefreshToken(RefreshToken token);
    void deleteByUser(User user);
} 