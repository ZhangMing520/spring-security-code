package com.example.springsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author zhangming
 * @date 2020/7/30 0:02
 * <p>
 * /admiin/api/ 系统后台管理 API
 * /app/api 公开访问API
 * /user/api  用户操作自身数据API
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    /**
     * @param http
     * @throws Exception ant ? 表示任意当个字符
     *                   * 匹配0或者任意数量字符
     *                   ** 0或者多个目录
     *                   <p>
     *                   hasRole  判断会添加前缀   hasAuthority 不会添加前缀
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and()
                .authorizeRequests()
                .antMatchers("/admin/api/**").hasRole("ADMIN")
                .antMatchers("/user/api/**").hasRole("USER")
                .antMatchers("/app/api/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin();
    }


}
