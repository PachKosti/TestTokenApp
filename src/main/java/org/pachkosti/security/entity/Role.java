package org.pachkosti.security.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
public enum Role {
    USER("User"),
    MODERATOR("Moderator"),
    ADMIN("Admin");

    private String name;

}
