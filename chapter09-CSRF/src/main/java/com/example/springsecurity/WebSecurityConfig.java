package com.example.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionListener;
import java.io.IOException;
import java.util.Arrays;

/**
 * @author zhangming
 * @date 2020/7/31 21:38
 *
 * {@link CsrfToken} 用于描述token值，以及验证应当获取哪个请求参数或请求头字段的接口
 *
 * {@link HttpSessionCsrfTokenRepository} CsrfToken 存储在 httpSession 中，
 * 并指定前端把 CsrfToken 值放在 _csrf 的请求参数或者名为 X-CSRF-TOKEN 的请求头字段，
 * 校验时候，通过对比 httpSession 内存储的 CsrfToken 与前端携带的 CsrfToken 是否一致
 *
 * {@link CookieCsrfTokenRepository} CsrfToken 存储在用户的 cookie 内，减少服务器 httpSession 存储的内存消耗；
 * cookie存储 CsrfToken，前端可以用 javaScript 获取（cookie httpOnly设置为 false）
 * cookie 只有同域的情况下才能被读取；服务器对 CsrfToken 校验并非取自 cookie ; cookie内 CsrfToken 值并没有被校验的作用，仅仅作为一个存储容器使用
 *
 * {@link CsrfFilter}  从请求参数或请求头字段获取页面 CsrfToken，与从cookie中获取的CsrfToken比较
 *
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/api/**").hasRole("ADMIN")
                .antMatchers("/user/api/**").hasRole("USER")
                .antMatchers("/app/api/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                // 启用 CORS 支持
                .formLogin()
        ;
    }

}
