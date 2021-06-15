package com.example.Spring.Security.SecurityConfig;

public enum ApplicationRolePermissions {
    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

    private final String permission;
    ApplicationRolePermissions(String permission) {
        this.permission = permission;
    }
    public String getPermission() {
        return permission;
    }
}
