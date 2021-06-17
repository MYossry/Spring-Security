package com.example.Spring.Security.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> getApplicationUserByUserName(String userName);
}
