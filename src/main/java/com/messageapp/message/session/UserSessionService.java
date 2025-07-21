package com.messageapp.message.session;

import com.messageapp.message.entity.User;
import com.messageapp.message.entity.RefreshToken;
import com.messageapp.message.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserSessionService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ObjectMapper objectMapper;
    private static final String SESSION_PREFIX = "user_session:";

    public String saveSession(User user, String ipAddress, String deviceId, String refreshToken) {
        removeSessionByUserId(user.getId());
        String sessionId = UUID.randomUUID().toString();
        UserSession session = new UserSession(
                sessionId,
                user.getId(),
                ipAddress,
                deviceId,
                refreshToken,
                Instant.now()
        );
        redisTemplate.opsForValue().set(SESSION_PREFIX + user.getId(), session);
        return sessionId;
    }

    public Optional<UserSession> getSessionByUserId(Long userId) {
        Object session = redisTemplate.opsForValue().get(SESSION_PREFIX + userId);
        if (session != null) {
            try {
                UserSession userSession = objectMapper.convertValue(session, UserSession.class);
                return Optional.of(userSession);
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public Optional<UserSession> getSessionBySessionId(String sessionId) {
        return Optional.empty();
    }

    public void updateRefreshTokenInSession(Long userId, String newRefreshToken) {
        Optional<UserSession> sessionOpt = getSessionByUserId(userId);
        if (sessionOpt.isPresent()) {
            UserSession session = sessionOpt.get();
            session.setRefreshToken(newRefreshToken);
            redisTemplate.opsForValue().set(SESSION_PREFIX + userId, session);
        }
    }

    public void removeSessionByUserId(Long userId) {
        redisTemplate.delete(SESSION_PREFIX + userId);
    }
} 