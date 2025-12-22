package com.ejetcore.authenticationservice;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserModel, Long> {

    Optional<UserModel> findByGoogleSub(String googleSub);

    Optional<UserModel> findByEmail(String email);
}

