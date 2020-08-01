//package com.example.springsecurity.service;
//
//import com.example.springsecurity.mapper.UserMapper;
//import com.example.springsecurity.po.User;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.AuthorityUtils;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import org.springframework.util.StringUtils;
//
//import java.util.Collections;
//import java.util.List;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
//
////@Service
//public class MyUserDetailsServiceImpl implements UserDetailsService {
//
//    @Autowired
//    private UserMapper userMapper;
//
//    /**
//     * {@link AuthorityUtils#commaSeparatedStringToAuthorityList} 默认使用逗号分隔
//     * <p>
//     * 每个角色对应一个 SimpleGrantedAuthority
//     *
//     * @param username
//     * @return
//     * @throws UsernameNotFoundException
//     */
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        User user = userMapper.findByUserName(username);
//        if (user == null) {
//            throw new UsernameNotFoundException("用户不存在");
//        }
//
//        List<GrantedAuthority> authorityList = AuthorityUtils.commaSeparatedStringToAuthorityList(user.getRoles());
//        user.setAuthorities(authorityList);
//
//        return user;
//    }
//
//    /**
//     * ; 分隔
//     *
//     * @param roles
//     * @return
//     */
//    private List<GrantedAuthority> generateAuthorities(String roles) {
//        if (StringUtils.isEmpty(roles)) {
//            return Collections.emptyList();
//        }
//
//        List<GrantedAuthority> authorities = Stream.of(roles.split(";"))
//                .map(role -> new SimpleGrantedAuthority(role))
//                .collect(Collectors.toList());
//
//        return authorities;
//    }
//
//}
