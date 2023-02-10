package org.pachkosti.security.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@AllArgsConstructor
@Setter
@Getter
public class User {
    private Long id;
    private String userName;
    private String password;
    private String email;
    private List<Role> roles;
}
