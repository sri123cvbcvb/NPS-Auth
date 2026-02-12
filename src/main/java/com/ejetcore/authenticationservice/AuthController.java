package com.ejetcore.authenticationservice;


import com.ejetcore.dto.UserDto;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.util.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;


import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RedisSessionService redisSessionService;

    // ====================================
    // 1) GET /api/auth/me  (Protected)
    // ====================================

    @GetMapping("/login/google")    //localhost:8089/api/auth/login/google
    public void loginWithGoogle(HttpServletResponse response) throws IOException {
        // redirect to backend OAuth2 login entry point
        response.sendRedirect("/oauth2/authorization/google");
    }

    // ====================================
    // 2) GET /api/auth/me  (Protected)
    // ====================================
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {

        if (authentication == null || !(authentication.getPrincipal() instanceof UserModel)) {
            // Should not normally happen because endpoint is protected
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "authenticated", false,
                            "message", "User is not authenticated"
                    ));
        }

        UserModel user = (UserModel) authentication.getPrincipal();

        UserDto userDto = UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .pictureUrl(user.getPictureUrl())
                .emailVerified(user.getEmailVerified())
                .role(user.getRole())
                .build();

        return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "user", userDto
        ));
    }

    // ====================================
    // 3) POST /api/auth/logout  (Protected)
    // ====================================
    /*@PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            @CookieValue(value = "EJET_AUTH", required = false) String jwtCookie,
            HttpServletResponse response
    ) {

        String token = null;

        // 1) Try to get token from Authorization header (old behavior)
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7); // remove "Bearer "
        }

        // 2) If no header, try JWT from cookie (new browser flow)
        if (!StringUtils.hasText(token) && StringUtils.hasText(jwtCookie)) {
            token = jwtCookie;
        }

        if (StringUtils.hasText(token)) {
            // delete from Redis (our session store)
            redisSessionService.deleteSession(token);
        }

        // Clear security context for current request
        SecurityContextHolder.clearContext();

        // 3) Remove JWT cookie
        Cookie authCookie = new Cookie("EJET_AUTH", "");
        authCookie.setPath("/");
        authCookie.setHttpOnly(true);
        authCookie.setSecure(false); // 🔴 set true in production with HTTPS
        authCookie.setMaxAge(0);     // delete cookie
        response.addCookie(authCookie);

        // 4) Remove user info cookie
        Cookie userCookie = new Cookie("EJET_USER", "");
        userCookie.setPath("/");
        userCookie.setHttpOnly(false);
        userCookie.setSecure(false);
        userCookie.setMaxAge(0);
        response.addCookie(userCookie);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Logged out successfully"
        ));
    }*/


    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            @CookieValue(value = "EJET_AUTH", required = false) String jwtCookie,
            HttpServletResponse response
    ) {

        String token = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (!StringUtils.hasText(token) && StringUtils.hasText(jwtCookie)) {
            token = jwtCookie;
        }

        if (StringUtils.hasText(token)) {
            redisSessionService.deleteSession(token);
        }

        SecurityContextHolder.clearContext();

        // Use ResponseCookie to delete cookies (match attributes used when creating them)
        // NOTE: For cross-site cookies in prod you will want SameSite=None and secure=true
        ResponseCookie clearJwt = ResponseCookie.from("EJET_AUTH", "")
                .httpOnly(true)
                .secure(false)            // set true in production (HTTPS)
                .path("/")               // MUST match login cookie path
                .sameSite("Lax")         // match login cookie's SameSite
                .maxAge(0)
                .build();

        ResponseCookie clearUser = ResponseCookie.from("EJET_USER", "")
                .httpOnly(false)
                .secure(false)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, clearJwt.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, clearUser.toString());

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Logged out successfully"
        ));
    }


}
