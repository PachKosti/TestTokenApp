package org.pachkosti.security.service;

import lombok.AllArgsConstructor;
import org.pachkosti.security.entity.Role;
import org.pachkosti.security.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
//    @Autowired
//    UserRepository userRepository;

    private static final PasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
//    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
        Map<String, User> users = new HashMap<>();
        fillUsersMap(users);
        User user = users.get(username);

        return UserDetailsImpl.build(user);
    }

    private void fillUsersMap(Map<String, User> users){
        List<Role> roles = new ArrayList<>();
        roles.add(Role.USER);
        for(int i = 0;  i <= 10; i++){
            User user = new User(Long.valueOf(i), "user" + i, encoder.encode("password" + i), "email", roles);
            users.put(user.getUserName(), user);
        }

    }
}