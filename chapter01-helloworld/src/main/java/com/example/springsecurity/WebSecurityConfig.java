package com.example.springsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author zhangming
 * @date 2020/7/30 0:02
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    /**
     * 访问 http://localhost:8080/myLogin.html
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/myLogin.html")
                // 指定处理登录请求的路径
                .loginProcessingUrl("/login")
                /**
                 *  指定登录成功时候的处理逻辑
                 *
                 *  一般管理，在发送请求登录并认证成功之后，页面会跳转到原始页面；前后端分离系统，
                 *  需要依靠JSON告知前端成功登录与否
                 */
                .successHandler(new AuthenticationSuccessHandler() {

                    /**
                     *
                     * @param httpServletRequest
                     * @param httpServletResponse
                     * @param authentication  携带当前登录用户名以及角色等信息
                     * @throws IOException
                     * @throws ServletException
                     */
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=UTF-8");
                        PrintWriter writer = httpServletResponse.getWriter();
                        writer.write("{\"error_code\":\"0\",\"message\":\"欢迎登录系统\"}");
                    }
                })
                // 指定登录失败时候的处理逻辑
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=UTF-8");
                        PrintWriter writer = httpServletResponse.getWriter();
                        writer.write("{\"error_code\":\"401\",\"message\":\"" + e.getMessage() + "\"}");
                    }
                })
                // 登录页面不设限制访问
                .permitAll()
                .and()
                .csrf().disable();
    }
}
