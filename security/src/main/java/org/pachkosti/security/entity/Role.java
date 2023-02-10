package org.pachkosti.security.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Role {
    USER("User"),
    MODERATOR("Moderator"),
    ADMIN("Admin");

    private String name;

}
