package org.pachkosti.security;

import org.pachkosti.security.jwt.AuthEntryPointJwt;
import org.pachkosti.security.filter.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity
public class SecurityConfig  {

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

//    @Bean
//    public OncePerRequestFilter oncePerRequestFilter() {
//        return new AuthTokenFilter();
//    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
//        return new UserDetailsServiceImpl(passwordEncoder);
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthTokenFilter authenticationJwtTokenFilter) throws Exception {
        http.cors().and().csrf().disable().headers().httpStrictTransportSecurity().disable().and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .addFilterBefore(authenticationJwtTokenFilter, AnonymousAuthenticationFilter.class)
                .authorizeRequests()//.antMatchers("/test/**").permitAll()
//                .antMatchers("/test/**").permitAll()
                .antMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated();
        return http.build();
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.httpBasic().disable()
//                .authorizeRequests().antMatchers("/test/**").permitAll()
////                .antMatchers("/test/**").permitAll()
//                .anyRequest().authenticated();;
//        return http.build();
//    }
}