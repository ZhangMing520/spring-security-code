package com.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * @author zhangming
 * @date 2020/7/31 21:38
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private DataSource dataSource;

    /**
     * 每个 csrf  cors 表单登录，都对应一个过滤链
     *
     * @param http
     * @throws Exception
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
//        jdbcTokenRepository.setDataSource(dataSource);
//
//        http.authorizeRequests()
//                .antMatchers("/admin/api/**").hasAnyAuthority("ROLE_ADMIN")
//                .antMatchers("/user/api/**").hasAnyAuthority("USER")
//                .antMatchers("/app/api/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .csrf().disable()
//                .formLogin()
//                .and()
//                .rememberMe().userDetailsService(userDetailsService)
//                // 散列令牌 指定生成令牌的key
////        .key("tokenKey")
//
//                // 持久化令牌 自定义tokenRepository
//                .tokenRepository(jdbcTokenRepository)
//        ;
//    }


    /**
     * logout 是由多个 LogoutHandler 流式处理
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.logout()
                // 指定接受注销请求的路由
                .logoutUrl("/myLogout")
                // 注销成功，重定向到该路径下
                .logoutSuccessUrl("/")
                //  注销成功的处理方式
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

                    }
                })
                // httpSession 失效
                .invalidateHttpSession(true)
                // 删除cookie
                .deleteCookies("cookie1", "cookie2")
                // 定义清理策略 LogoutSuccessHandler 也可以做到
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

                    }
                });
    }
}
