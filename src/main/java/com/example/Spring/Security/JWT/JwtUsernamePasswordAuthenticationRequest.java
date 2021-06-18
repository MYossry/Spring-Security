package com.example.Spring.Security.JWT;

public class JwtUsernamePasswordAuthenticationRequest {

    private String userName;
    private String password;

    public JwtUsernamePasswordAuthenticationRequest(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }

    public JwtUsernamePasswordAuthenticationRequest() {
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
