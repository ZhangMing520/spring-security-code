package com.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

@SpringBootApplication
public class FormAuthenticateApplication {

    public static void main(String[] args) {
        SpringApplication.run(FormAuthenticateApplication.class, args);
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        // 内存的多用户支持
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//
//        manager.createUser(User.withUsername("user").password("123").roles("USER").build());
//        manager.createUser(User.withUsername("admin").password("123").roles("ADMIN").build());
//
//        return manager;
//    }


    @Autowired
    private DataSource dataSource;

    @Bean
    public UserDetailsService userDetailsService() {
        // 内存的多用户支持
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
        manager.setDataSource(dataSource);

        // createUser 实际执行了SQL，每次重启都会执行
        // insert into users() values()
        // authorities 表实际保存内容 ROLE_ADMIN/ROLE_USER
        if (!manager.userExists("user")) {
            manager.createUser(User.withUsername("user").password("123").roles("USER").build());
        }
        if (!manager.userExists("admin")) {
            manager.createUser(User.withUsername("admin").password("123").roles("ADMIN").build());
        }

        return manager;
    }

}
