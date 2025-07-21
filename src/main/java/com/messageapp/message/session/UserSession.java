package com.messageapp.message.session;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSession implements Serializable {
    private String sessionId;
    private Long userId;
    private String ipAddress;
    private String deviceId;
    private String refreshToken;
    private Instant creationTimestamp;
} 