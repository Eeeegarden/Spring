package com.example.TestSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 비밀번호 암호화 메서드
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 계층구조 hierarchy 설정
    // 6.3.x 이후 버전
    @Bean
    public RoleHierarchy roleHierarchy() {

        return RoleHierarchyImpl.fromHierarchy("""
            ROLE_ADMIN > ROLE_MANAGER
            ROLE_MANAGER > ROLE_USER
            """);
    }

    @Bean
    public SecurityFilterChain fiterChain(HttpSecurity http) throws Exception{

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/join", "/joinProc").permitAll()
                        .requestMatchers("/").hasAnyRole("USER")
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/manager").hasRole("MANAGER")
                        .requestMatchers("/my/**").hasAnyRole("USER")
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll()
                );

        // csrf 설정
        // API 서버의 경우 보통 세션을 STATELESS로 관리하기 때문에 disable 가능
        // 배포환경에서는 csrf 공격 방지를 위해 추가설정 필요
        http
                .csrf((auth) -> auth.disable());

        // 세션 설정
        http
                .sessionManagement((auth) -> auth
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true));

        http
                .sessionManagement(((auth) -> auth
                        .sessionFixation().changeSessionId()));

        return http.build();
    }
}