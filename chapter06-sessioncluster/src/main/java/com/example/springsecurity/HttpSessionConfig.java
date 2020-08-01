package com.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

/**
 * @author zhangming
 * @date 2020/8/1 11:44
 * <p>
 * 启用基于redis的httpSession实现
 */
@EnableRedisHttpSession
public class HttpSessionConfig {

    /**
     * 提供 redis 连接， 默认是 localhost 6369
     *
     * @return
     */
    @Bean
    public RedisConnectionFactory connectionFactory() {
        return new JedisConnectionFactory();
    }

    @Autowired
    private FindByIndexNameSessionRepository sessionRepository;

    /**
     * {@link SpringSessionBackedSessionRegistry}
     * 是session为spring security 提供的用于在集群环境下控制会话并发的会话注册表实现类
     * @return
     */
    @Bean
    public SpringSessionBackedSessionRegistry sessionRegistry(){
        return new SpringSessionBackedSessionRegistry(sessionRepository);
    }

    /**
     * httpSession 的事件监听，修改 session 提供的会话注册表
     * @return
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher(){
        return new HttpSessionEventPublisher();
    }

}
