package com.ejetcore.security;

import com.ejetcore.authenticationservice.GoogleTokenModel;
import com.ejetcore.authenticationservice.GoogleTokenRepository;
import com.ejetcore.authenticationservice.RedisSessionService;
import com.ejetcore.authenticationservice.UserModel;
import com.ejetcore.authenticationservice.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final GoogleTokenRepository googleTokenRepository;
    private final RedisSessionService redisSessionService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenEncryptionUtil tokenEncryptionUtil;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Centralized UTC "now" */
    private static LocalDateTime nowUtc() {
        return LocalDateTime.ofInstant(Instant.now(), ZoneOffset.UTC);
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Unexpected authentication type: " + authentication.getClass().getName()
            );
            return;
        }

        // ==========================
        // 1) Extract Google user info
        // ==========================
        OAuth2User oauthUser = oauthToken.getPrincipal();
        Map<String, Object> attributes = oauthUser.getAttributes();

        String sub = (String) attributes.get("sub");
        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", "");
        String picture = (String) attributes.getOrDefault("picture", "");
        Boolean emailVerified =
                (Boolean) attributes.getOrDefault("email_verified", Boolean.FALSE);

        if (StringUtils.isBlank(sub)) {
            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Google 'sub' (user ID) is missing"
            );
            return;
        }

        // ==========================
        // 2) Create / update User (UTC)
        // ==========================
        UserModel user = userRepository.findByGoogleSub(sub)
                .orElseGet(() -> {
                    UserModel u = new UserModel();
                    u.setGoogleSub(sub);
                    u.setRole("ROLE_USER");
                    u.setCreatedAt(nowUtc());
                    return u;
                });

        user.setEmail(email);
        user.setName(name);
        user.setPictureUrl(picture);
        user.setEmailVerified(Boolean.TRUE.equals(emailVerified));
        user.setUpdatedAt(nowUtc());

        UserModel savedUser = userRepository.save(user);

        // ==========================
        // 3) Store Google access token (UTC)
        // ==========================
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(
                        oauthToken.getAuthorizedClientRegistrationId(),
                        oauthToken.getName()
                );

        if (client != null) {
            OAuth2AccessToken accessToken = client.getAccessToken();
            if (accessToken != null) {

                String rawToken = accessToken.getTokenValue();

                //  Google expiry is Instant (UTC by definition) → store explicitly in UTC
                LocalDateTime accessExpiresAtUtc =
                        accessToken.getExpiresAt() != null
                                ? LocalDateTime.ofInstant(
                                accessToken.getExpiresAt(),
                                ZoneOffset.UTC
                        )
                                : null;

                GoogleTokenModel googleToken =
                        googleTokenRepository.findByUser(savedUser)
                                .orElseGet(() -> {
                                    GoogleTokenModel t = new GoogleTokenModel();
                                    t.setUser(savedUser);
                                    t.setCreatedAt(nowUtc());
                                    return t;
                                });

                googleToken.setAccessTokenEncrypted(
                        tokenEncryptionUtil.encrypt(rawToken)
                );
                googleToken.setAccessExpiresAt(accessExpiresAtUtc);
                googleToken.setUpdatedAt(nowUtc());

                googleTokenRepository.save(googleToken);
            }
        }

        // ==========================
        // 4) JWT + Redis session
        // ==========================
        String role =
                savedUser.getRole() != null ? savedUser.getRole() : "ROLE_USER";

        String existingToken = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("EJET_AUTH".equals(c.getName())) {
                    existingToken = c.getValue();
                    break;
                }
            }
        }

        String jwtToUse = null;

        if (StringUtils.isNotBlank(existingToken)
                && jwtTokenProvider.validateToken(existingToken)) {

            Long redisUserId =
                    redisSessionService.getUserIdFromSession(existingToken);

            if (redisUserId != null && redisUserId.equals(savedUser.getId())) {
                jwtToUse = existingToken; // reuse
            }
        }

        if (jwtToUse == null) {
            jwtToUse = jwtTokenProvider.generateToken(
                    savedUser.getId(),
                    savedUser.getEmail(),
                    role
            );
            redisSessionService.storeSession(jwtToUse, savedUser.getId());
        }

        // ==========================
        // 5) Cookies + Redirect
        // ==========================
        ResponseCookie jwtCookie = ResponseCookie.from("EJET_AUTH", jwtToUse)
                .httpOnly(true)
                .secure(true)     // HTTPS in prod
                .path("/")
                .sameSite("Lax")
                .maxAge(jwtTokenProvider.getJwtExpirationMs() / 1000)
                .build();

        String rawUserInfo =
                savedUser.getId() + "::" +
                        (savedUser.getEmail() != null ? savedUser.getEmail() : "") + "::" +
                        (savedUser.getName() != null ? savedUser.getName() : "") + "::" +
                        role;

        String encodedUserInfo =
                URLEncoder.encode(rawUserInfo, StandardCharsets.UTF_8);

        ResponseCookie userCookie = ResponseCookie.from("EJET_USER", encodedUserInfo)
                .httpOnly(false)
                .secure(true)
                .path("/")
                .sameSite("Lax")
                .maxAge(jwtTokenProvider.getJwtExpirationMs() / 1000)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, userCookie.toString());

        response.sendRedirect("/api/auth/me");
    }
}
