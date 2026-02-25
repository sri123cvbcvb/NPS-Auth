package com.ejetcore.security;

import com.ejetcore.authenticationservice.RedisSessionService;
import com.ejetcore.authenticationservice.UserModel;
import com.ejetcore.authenticationservice.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final RedisSessionService redisSessionService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String token = resolveToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {

            Long userIdFromToken = jwtTokenProvider.getUserIdFromToken(token);

            // Check Redis but in a safe way
            Long redisUserId = redisSessionService.getUserIdFromSession(token);

            if (redisUserId != null && redisUserId >= 0) {
                // Redis ok and session exists
                if (!redisUserId.equals(userIdFromToken)) {
                    // token tampered or expired in Redis – ignore token
                    filterChain.doFilter(request, response);
                    return;
                }
            } else if (redisUserId == null) {
                // No session found in Redis → treat as invalid token
                filterChain.doFilter(request, response);
                return;
            } else if (redisUserId == -1L) {
                // Redis error → fallback to JWT only (still allow auth)
                // no additional checks
            }

            Optional<UserModel> userOpt = userRepository.findById(userIdFromToken);
            if (userOpt.isPresent()) {
                UserModel user = userOpt.get();
                String role = jwtTokenProvider.getRoleFromToken(token);
                if (role == null) role = "ROLE_USER";

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                user,
                                null,
                                List.of(new SimpleGrantedAuthority(role))
                        );

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        // 1) Try Authorization header (Postman / Swagger)
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // 2) Try HttpOnly cookie "EJET_AUTH" (browser flow)
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("EJET_AUTH".equals(cookie.getName())) {
                    String value = cookie.getValue();
                    if (StringUtils.hasText(value)) {
                        return value;
                    }
                }
            }
        }

        return null;
    }
}
