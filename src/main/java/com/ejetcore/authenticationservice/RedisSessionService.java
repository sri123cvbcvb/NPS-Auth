package com.ejetcore.authenticationservice;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisSessionService {

    private final StringRedisTemplate stringRedisTemplate;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    private String sessionKey(String token) {
        return "SESSION:" + token;
    }

    private String userSessionKey(Long userId) {
        return "USER_SESSION:" + userId;
    }

    /**
     * Store session safely in Redis.
     * This implementation maintains reverse mapping USER_SESSION:<userId> -> token.
     * If a user already had a token, the old SESSION:<oldToken> is deleted so we keep one session per user.
     */
    public void storeSession(String token, Long userId) {
        if (token == null || userId == null) return;

        try {
            String userKey = userSessionKey(userId);
            String existingToken = stringRedisTemplate.opsForValue().get(userKey);

            // Delete old SESSION:<oldToken> if present and different
            if (existingToken != null && !existingToken.isEmpty() && !existingToken.equals(token)) {
                try {
                    stringRedisTemplate.delete(sessionKey(existingToken));
                } catch (Exception e) {
                    log.warn("Failed to delete previous session key for user {}: {}", userId, e.getMessage());
                }
            }

            Duration ttl = Duration.ofMillis(jwtExpirationMs);

            // Set SESSION:<token> -> userId
            stringRedisTemplate.opsForValue().set(sessionKey(token), String.valueOf(userId), ttl);

            // Set USER_SESSION:<userId> -> token
            stringRedisTemplate.opsForValue().set(userKey, token, ttl);
        } catch (Exception e) {
            log.error("Failed to store session in Redis", e);
        }
    }

    /**
     * @return userId if session exists;
     *         null if no session;
     *         -1L if Redis had an error (to allow fallback)
     */
    public Long getUserIdFromSession(String token) {
        if (token == null) return null;
        try {
            String value = stringRedisTemplate.opsForValue().get(sessionKey(token));
            if (value == null) {
                return null;
            }
            return Long.valueOf(value);
        } catch (Exception e) {
            log.error("Failed to read session from Redis", e);
            return -1L; // special value = redis error
        }
    }

    /**
     * Returns token associated with a user, or null.
     */
    public String getSessionForUser(Long userId) {
        if (userId == null) return null;
        try {
            return stringRedisTemplate.opsForValue().get(userSessionKey(userId));
        } catch (Exception e) {
            log.error("Failed to read user session mapping from Redis", e);
            return null;
        }
    }

    /**
     * Delete session by token, and clean up the user->token mapping if it points to this token.
     */
    public void deleteSession(String token) {
        if (token == null) return;

        try {
            String sKey = sessionKey(token);
            String userIdStr = stringRedisTemplate.opsForValue().get(sKey);
            stringRedisTemplate.delete(sKey);

            if (userIdStr != null) {
                try {
                    Long userId = Long.valueOf(userIdStr);
                    String userKey = userSessionKey(userId);
                    String mapped = stringRedisTemplate.opsForValue().get(userKey);
                    if (token.equals(mapped)) {
                        stringRedisTemplate.delete(userKey);
                    }
                } catch (NumberFormatException ignored) {
                    // ignore
                }
            }
        } catch (Exception e) {
            log.error("Failed to delete session in Redis", e);
        }
    }
}
