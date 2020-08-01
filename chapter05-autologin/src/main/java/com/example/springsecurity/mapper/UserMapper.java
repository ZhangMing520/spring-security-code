package com.example.springsecurity.mapper;

import com.example.springsecurity.po.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

@Repository
public interface UserMapper {

    @Select("select * from users where username =#{username}")
    User findByUserName(@Param("username") String username);

}
