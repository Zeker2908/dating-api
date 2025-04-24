package ru.zeker.authenticationservice.domain.model.enums;

public enum Role {
    USER,
    ADMIN;

    public static Role fromString(String role) {
        for (Role r : Role.values()) {
            if (r.name().equalsIgnoreCase(role)) {
                return r;
            }
        }
        throw new IllegalArgumentException("Неизвестная роль: " + role);
    }
}
