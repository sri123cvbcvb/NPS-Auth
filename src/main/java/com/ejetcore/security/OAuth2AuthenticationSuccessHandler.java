package com.ejetcore.security;

import com.ejetcore.authenticationservice.GoogleTokenModel;
import com.ejetcore.authenticationservice.GoogleTokenRepository;
import com.ejetcore.authenticationservice.RedisSessionService;
import com.ejetcore.authenticationservice.UserModel;
import com.ejetcore.authenticationservice.UserRepository;
import com.ejetcore.dto.AuthResponseDto;
import com.ejetcore.dto.UserDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.http.Cookie;

import java.io.IOException;
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

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Unexpected authentication type: " + authentication.getClass().getName());
            return;
        }

        OAuth2User oauthUser = oauthToken.getPrincipal();
        Map<String, Object> attributes = oauthUser.getAttributes();

        String sub = (String) attributes.get("sub");
        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", "");
        String picture = (String) attributes.getOrDefault("picture", "");
        Boolean emailVerified = (Boolean) attributes.getOrDefault("email_verified", Boolean.FALSE);

        if (StringUtils.isBlank(sub)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Google 'sub' (user ID) is missing");
            return;
        }

        // ==========================
        // 1) Save / update UserModel
        // ==========================
        UserModel user = userRepository.findByGoogleSub(sub)
                .orElseGet(() -> {
                    UserModel u = new UserModel();
                    u.setGoogleSub(sub);
                    u.setRole("ROLE_USER");
                    u.setCreatedAt(LocalDateTime.now());
                    return u;
                });

        user.setEmail(email);
        user.setName(name);
        user.setPictureUrl(picture);
        user.setEmailVerified(emailVerified != null && emailVerified);
        user.setUpdatedAt(LocalDateTime.now());

        UserModel users = userRepository.save(user);

        // ==========================
        // 2) Save Google access token
        // ==========================
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(
                        oauthToken.getAuthorizedClientRegistrationId(),
                        oauthToken.getName()
                );

        if (client != null) {
            OAuth2AccessToken accessToken = client.getAccessToken();
            if (accessToken != null) {
                String tokenValue = accessToken.getTokenValue();
                LocalDateTime expiresAt = accessToken.getExpiresAt() != null
                        ? LocalDateTime.ofInstant(accessToken.getExpiresAt(), ZoneOffset.UTC)
                        : null;

                GoogleTokenModel googleToken = googleTokenRepository.findByUser(user)
                        .orElseGet(() -> {
                            GoogleTokenModel t = new GoogleTokenModel();
                            t.setUser(users);
                            t.setCreatedAt(LocalDateTime.now());
                            return t;
                        });

                googleToken.setAccessTokenEncrypted(
                        tokenEncryptionUtil.encrypt(tokenValue)
                );

                googleToken.setAccessExpiresAt(expiresAt);
                googleToken.setUpdatedAt(LocalDateTime.now());

                googleTokenRepository.save(googleToken);
            }
        }

        // ==========================
// 3) Create / reuse JWT + store in Redis (avoid duplicate sessions)
// ==========================
        String role = user.getRole() != null ? user.getRole() : "ROLE_USER";

// Try to reuse existing token from cookie (Option A)
        String cookieToken = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("EJET_AUTH".equals(c.getName())) {
                    cookieToken = c.getValue();
                    break;
                }
            }
        }

        String tokenToUse = null;

// If we found a cookie token and it is valid and points to same user in Redis — reuse it
        if (StringUtils.isNotBlank(cookieToken) && jwtTokenProvider.validateToken(cookieToken)) {
            Long redisUserId = redisSessionService.getUserIdFromSession(cookieToken);
            if (redisUserId != null && redisUserId.equals(users.getId())) {
                tokenToUse = cookieToken; // reuse
            }
        }

// Otherwise generate new token and store (Option B via RedisSessionService handles cleanup)
        if (tokenToUse == null) {
            tokenToUse = jwtTokenProvider.generateToken(users.getId(), users.getEmail(), role);
            // storeSession will remove any previous token for this user (if exists)
            redisSessionService.storeSession(tokenToUse, users.getId());
        }


        // ==========================
// 4) Set Cookies + Redirect to React
// ==========================



// 4A) Create HttpOnly Cookie for JWT
        ResponseCookie jwtCookie = ResponseCookie.from("EJET_AUTH", tokenToUse)
                .httpOnly(true)
                .secure(false)     // 🔴 set true in production (HTTPS)
                .path("/")
                .sameSite("Lax")
                .maxAge(jwtTokenProvider.getJwtExpirationMs() / 1000)
                .build();

// 4B) Create user info cookie (readable by React)
        String rawUserInfo =
                users.getId() + "::" +
                        (users.getEmail() != null ? users.getEmail() : "") + "::" +
                        (users.getName() != null ? users.getName() : "") + "::" +
                        role;

        String encodedUserInfo = URLEncoder.encode(rawUserInfo, StandardCharsets.UTF_8);

        ResponseCookie userCookie = ResponseCookie.from("EJET_USER", encodedUserInfo)
                .httpOnly(false)   // ✅ React can read this
                .secure(false)
                .path("/")
                .sameSite("Lax")
                .maxAge(jwtTokenProvider.getJwtExpirationMs() / 1000)
                .build();

// 4C) Add cookies to response
        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, userCookie.toString());

// 4D) Redirect to React app (NO token in URL)
        response.sendRedirect("http://localhost:5173/auth/callback");

// STOP execution — do NOT write JSON response

    }
}
