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
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSessionListener;
import java.io.IOException;

/**
 * @author zhangming
 * @date 2020/7/31 21:38
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    /**
     * $2a$12xxxx/yyyy
     * 2a 算法的版本  12 成本参数 表明该密文需要迭代的次数 12->2的12次方，即4096次 BCrypt 依靠次参数来限制算法的速度
     * <p>
     * 前22位是密文的随机盐值，最后31位是真正的散列值
     * <p>
     * 用户登录时候，需要同步取得用户输入的密码以及数据存储中的 BCrypt 密文，从密文中提取盐值和成本参数，与用户的密码进行一次  BCrypt 加密，最后比较两个密文是否一致
     *
     * @return
     */
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder(12);
//    }


    /**
     * 事件源（会话清理订阅 spring 事件，而非原生 HTTPSessionEvent）
     * <p>
     * 注册到Ioc容器中，将 java事件转化为 spring 事件
     *
     * @return
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }


    /**
     * {@link ConcurrentSessionControlAuthenticationStrategy} 实现会话管理
     *
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
                .formLogin()
                .and()
//        Spring Security 4.x 启用CSRF防御后logout只能是POST请求
                .logout()
                // HTTP GET与注销  一般不推荐
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and()
                .sessionManagement().maximumSessions(1)
                // 阻止新会话登录
                .maxSessionsPreventsLogin(true)
        ;
    }

}
