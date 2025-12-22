package com.ejetcore.authenticationservice;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GoogleTokenRepository extends JpaRepository<GoogleTokenModel, Long> {

    Optional<GoogleTokenModel> findByUser(UserModel user);

    Optional<GoogleTokenModel> findByUserId(Long userId);
}

