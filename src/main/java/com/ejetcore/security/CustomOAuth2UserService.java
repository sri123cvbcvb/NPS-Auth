/*
package com.ejetcore.security;


import com.ejetcore.authenticationService.UserModel;
import com.ejetcore.authenticationService.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        Map<String, Object> attributes = oAuth2User.getAttributes();

        String sub = (String) attributes.get("sub");
        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", "");
        String picture = (String) attributes.getOrDefault("picture", "");
        Boolean emailVerified = (Boolean) attributes.getOrDefault("email_verified", Boolean.FALSE);

        if (StringUtils.isBlank(sub)) {
            throw new IllegalStateException("Google 'sub' (user ID) is missing");
        }

        UserModel user = userRepository.findByGoogleSub(sub)
                .orElseGet(() -> {
                    UserModel newUser = new UserModel();
                    newUser.setGoogleSub(sub);
                    newUser.setRole("ROLE_USER");
                    return newUser;
                });

        user.setEmail(email);
        user.setName(name);
        user.setPictureUrl(picture);
        user.setEmailVerified(emailVerified != null && emailVerified);

        user = userRepository.save(user);

        // wrap into our custom principal type
        return new CustomOAuth2User(oAuth2User, user.getId());
    }
}
*/
