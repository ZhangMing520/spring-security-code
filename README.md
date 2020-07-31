1. spring-security 最小依赖
```xml
<dependencies>
		<dependency>
			<groupId>org.springframework</groupId>
			<artifactId>spring-aop</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-config</artifactId>
			<exclusions>
				<exclusion>
					<groupId>aopalliance</groupId>
					<artifactId>aopalliance</artifactId>
				</exclusion>
			</exclusions>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-web</artifactId>
			<exclusions>
				<exclusion>
					<groupId>aopalliance</groupId>
					<artifactId>aopalliance</artifactId>
				</exclusion>
			</exclusions>
		</dependency>
	</dependencies>
```

2. WebSecurityConfigurerAdapter 默认声明的安全特性
- 验证所有请求
- 允许用户使用表单登录进行身份验证（spring security 提供了一个简单的表单登录页面）
- 允许用户使用 HTTP 基本认证
```java 
http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.formLogin().and()
			.httpBasic();
```

3. HttpSecurity 与命名空间配置的标签关系
> 调用下列方法之后，除非使用 and() 方法结束当前标签，上下文才会回到 HttpSecurity，否则链式调用的上下文将自动进入对应标签域
- http   <http>
- authorizeRequests()  <intercept-url>  返回一个 URL 拦截注册器，可以调用提供的 anyRequest() antMatchers() regexMatchers() 等方法来匹配系统的 URL，并为其指定安全策略
- formLogin()    <form-login>   表单认证方式  formLogin().loginPage()指定自定义登录页面
- httpBasic()    <http-basic>  表单认证方式  
- csrf()      <csrf>    跨站请求伪造防护功能



4.  SecurityConfigurer 接口

   >  SessionManagementConfigurer，CorsConfigurer，RememberMeConfigurer 都实现了SecurityConfigurer 接口；除了Spring Security 提供的过滤器外，我们可以添加自己的过滤器实现更多的安全功能，可以在 HttpSecurity 中实现



5. AuthenticationProvider 实现图形验证码

   > Spring Security中的主体（principal）。主体包含了所有能够经过验证而获得系统访问权限的用户、设备和其他系统。Spring Security通过一层包装将其定义为一个 Authentication。Authentication 中包含主体权限列表、主体凭据、主体详细信息，以及是否验证成功等信息。由于大部分场景下身份验证都是基于用户名和密码进行的，Spring Security 提供了一个 UsernamePasswordAuthenticationToken 用于代指这一类证明。UsernamePasswordAuthenticationToken 在各个 AuthenticationProvider 中流动，AuthenticationProvider  被定义为一个验证过程；一个完整的认证可以包含多个 AuthenticationProvider  ，一般由 ProviderManager 管理。ProviderManager 是由 UsernamePasswordAuthenticationFilter 调用的。所有的 AuthenticationProvider   包含的 Authentication 都来源于 UsernamePasswordAuthenticationFilter 
   
   >
   >
   >UsernamePasswordAuthenticationFilter  本身并没有设置用户详细信息的流程，而是通过标准接口 AuthenticationDetailsSource 构建的，

```java
public interface Authentication extends Principal, Serializable {
   
   // 获取主体权限列表
   Collection<? extends GrantedAuthority> getAuthorities();
// 获取主体凭据，通常为用户密码
   Object getCredentials();
// 获取主体携带的详细信息
   Object getDetails();
// 获取主体 通常为一个用户名
   Object getPrincipal();
// 主体是否验证成功
   boolean isAuthenticated();

   void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

```java
public interface AuthenticationProvider {
  
    // 验证过程 成功返回一个验证完成的 Authentication
   Authentication authenticate(Authentication authentication)
         throws AuthenticationException;
	// 是否支持验证当前的 Authentication 类型
   boolean supports(Class<?> authentication);
  
```

```java
public class UsernamePasswordAuthenticationFilter extends
      AbstractAuthenticationProcessingFilter {
   
   public Authentication attemptAuthentication(HttpServletRequest request,
         HttpServletResponse response) throws AuthenticationException {
      if (postOnly && !request.getMethod().equals("POST")) {
         throw new AuthenticationServiceException(
               "Authentication method not supported: " + request.getMethod());
      }

      String username = obtainUsername(request);
      String password = obtainPassword(request);

      if (username == null) {
         username = "";
      }

      if (password == null) {
         password = "";
      }

      username = username.trim();
		// 生成一个基本的 Authentication
      UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
            username, password);

      // 为改 Authentication 设置详细信息
      setDetails(request, authRequest);

   	// 调用 ProviderManager， 将Authentication传入认证流程
      return this.getAuthenticationManager().authenticate(authRequest);
   }
    
    protected void setDetails(HttpServletRequest request,
			UsernamePasswordAuthenticationToken authRequest) {
        // authenticationDetailsSource 构建详细信息，携带 HttpServletRequest 对象
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
```


6. Spring Security 提供了多钟常见的认证技术
   - HTTP层面的认证技术，包括HTTP基本认证和HTTP摘要认证两种
   - 基于LDAP的认证技术（Light weight Directory Access Protocol，轻量目录访问协议）
   - 聚焦于证明用户身份的OpenID认证技术
   - 聚焦于授权的 OAuth 认证技术
   - 系统内维护的用户名和密码认证技术

```java
public abstract class AbstractUserDetailsAuthenticationProvider implements
      AuthenticationProvider, InitializingBean, MessageSourceAware {

// 附加认证过程
   protected abstract void additionalAuthenticationChecks(UserDetails userDetails,
         UsernamePasswordAuthenticationToken authentication)
         throws AuthenticationException;
	
    // 认证过程
   public Authentication authenticate(Authentication authentication)
         throws AuthenticationException {
      Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
            messages.getMessage(
                  "AbstractUserDetailsAuthenticationProvider.onlySupports",
                  "Only UsernamePasswordAuthenticationToken is supported"));

      // Determine username
      String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
            : authentication.getName();

      boolean cacheWasUsed = true;
      UserDetails user = this.userCache.getUserFromCache(username);

      if (user == null) {
         cacheWasUsed = false;

         try {
             // 检索用户
            user = retrieveUser(username,
                  (UsernamePasswordAuthenticationToken) authentication);
         }
         catch (UsernameNotFoundException notFound) {
            logger.debug("User '" + username + "' not found");

            if (hideUserNotFoundExceptions) {
               throw new BadCredentialsException(messages.getMessage(
                     "AbstractUserDetailsAuthenticationProvider.badCredentials",
                     "Bad credentials"));
            }
            else {
               throw notFound;
            }
         }

         Assert.notNull(user,
               "retrieveUser returned null - a violation of the interface contract");
      }

      try {
          // 检查用户账号是否可用
         preAuthenticationChecks.check(user);
          // 附加认证
         additionalAuthenticationChecks(user,
               (UsernamePasswordAuthenticationToken) authentication);
      }
      catch (AuthenticationException exception) {
         if (cacheWasUsed) {
            // There was a problem, so try again after checking
            // we're using latest data (i.e. not from the cache)
            cacheWasUsed = false;
            user = retrieveUser(username,
                  (UsernamePasswordAuthenticationToken) authentication);
            preAuthenticationChecks.check(user);
            additionalAuthenticationChecks(user,
                  (UsernamePasswordAuthenticationToken) authentication);
         }
         else {
            throw exception;
         }
      }

       // 检查密码是否过期
      postAuthenticationChecks.check(user);

      if (!cacheWasUsed) {
         this.userCache.putUserInCache(user);
      }

      Object principalToReturn = user;

      if (forcePrincipalAsString) {
         principalToReturn = user.getUsername();
      }
// 返回一个认证通过的 
      return createSuccessAuthentication(principalToReturn, authentication, user);
   }

   // 检索用户
   protected abstract UserDetails retrieveUser(String username,
         UsernamePasswordAuthenticationToken authentication)
         throws AuthenticationException;

   public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
      this.forcePrincipalAsString = forcePrincipalAsString;
   }

    // 此认证过程支持 UsernamePasswordAuthenticationToken 及衍生对象
   public boolean supports(Class<?> authentication) {
      return (UsernamePasswordAuthenticationToken.class
            .isAssignableFrom(authentication));
   }
    
    ...
}
```

