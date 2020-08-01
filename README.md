##### 认证与授权

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

##### 图形验证码

4.  SecurityConfigurer 接口

   >  SessionManagementConfigurer，CorsConfigurer，RememberMeConfigurer 都实现了SecurityConfigurer 接口；除了Spring Security 提供的过滤器外，我们可以添加自己的过滤器实现更多的安全功能，可以在 HttpSecurity 中实现

```java
public interface SecurityConfigurer<O, B extends SecurityBuilder<O>> {

    // 各个配置器的初始化方法
   void init(B builder) throws Exception;
// 各个配置器被统一调用的配置方法
   void configure(B builder) throws Exception;
}
```

```java
public final class SessionManagementConfigurer<H extends HttpSecurityBuilder<H>>
    @Override
	public void configure(H http) throws Exception {
		SecurityContextRepository securityContextRepository = http
				.getSharedObject(SecurityContextRepository.class);
		SessionManagementFilter sessionManagementFilter = new SessionManagementFilter(
				securityContextRepository, getSessionAuthenticationStrategy(http));
		if (this.sessionAuthenticationErrorUrl != null) {
			sessionManagementFilter.setAuthenticationFailureHandler(
					new SimpleUrlAuthenticationFailureHandler(
							this.sessionAuthenticationErrorUrl));
		}
		InvalidSessionStrategy strategy = getInvalidSessionStrategy();
		if (strategy != null) {
			sessionManagementFilter.setInvalidSessionStrategy(strategy);
		}
		AuthenticationFailureHandler failureHandler = getSessionAuthenticationFailureHandler();
		if (failureHandler != null) {
			sessionManagementFilter.setAuthenticationFailureHandler(failureHandler);
		}
		AuthenticationTrustResolver trustResolver = http
				.getSharedObject(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			sessionManagementFilter.setTrustResolver(trustResolver);
		}
		sessionManagementFilter = postProcess(sessionManagementFilter);

    // sessionManagementFilter 添加到过滤器上
		http.addFilter(sessionManagementFilter);
		if (isConcurrentSessionControlEnabled()) {
			ConcurrentSessionFilter concurrentSessionFilter = createConccurencyFilter(http);

			concurrentSessionFilter = postProcess(concurrentSessionFilter);
			http.addFilter(concurrentSessionFilter);
		}
	}
}
```

```java
public final class HttpSecurity extends
      AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
      implements SecurityBuilder<DefaultSecurityFilterChain>,
      HttpSecurityBuilder<HttpSecurity> {
          
          // 将自定义过滤器添加到指定过滤器之后
    public HttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
            comparator.registerAfter(filter.getClass(), afterFilter);
            return addFilter(filter);
        }
          
          // 将自定义过滤器添加到指定过滤器之前
  public HttpSecurity addFilterBefore(Filter filter,
			Class<? extends Filter> beforeFilter) {
		comparator.registerBefore(filter.getClass(), beforeFilter);
		return addFilter(filter);
	}
        // 添加一个过滤器，必须是Spring security 自身提供的过滤器实例或者其继承过滤器
          // 详见 FilterComparator 
  public HttpSecurity addFilter(Filter filter) {
		Class<? extends Filter> filterClass = filter.getClass();
		if (!comparator.isRegistered(filterClass)) {
			throw new IllegalArgumentException(
					"The Filter class "
							+ filterClass.getName()
							+ " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
		}
		this.filters.add(filter);
		return this;
	}
         
          // 添加一个过滤器在自定义过滤器位置
     public HttpSecurity addFilterAt(Filter filter, Class<? extends Filter> atFilter) {
		this.comparator.registerAt(filter.getClass(), atFilter);
		return addFilter(filter);
	}

}
```



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

##### 自动登录和注销登录

7. 自动登录

   > 将用户的登录信息保存在用户浏览器的cookie中，当用户下次访问时候，自动实现校验并建立登录态的一种机制

- 用散列算法加密用户必要的登录信息并生成令牌；key 默认是随机生成的，重启服务，自动登录策略就会失效

- 数据库等持久性数据存储机制用的持久化令牌；最核心的是series和token两个值，都用MD5散列过的随机字符串；series仅在用户使用密码重新登录时更新，token会在每一个session中重新生成；

  > 解决了一个令牌可以同时在多端登录的问题，每个回话都会引发token的更新，即每个token仅支持单实例登录；

  > 解决了自动登录不会导致series变更，而每次自动登录都需要同时验证series和token两个值，当该令牌还未使用过自动登录就被盗取时候，系统会在非法用户验证通过后刷新token值，此时在合法用户浏览器中，该token已经失效。当合法用户使用自动登录时候，由于series对应的token不同，系统可以推断该令牌可能已经被盗用，从而做一些处理。例如清理该用户的所有自动登录令牌，并通知用户可能已经被盗号等

```java
hashInfo = md5Hex(username + ":" + expirationTime + ":" + password + ":" + key)
rememberCookie = base64(username + ":" + expirationTime + ":" + hashInfo )
```

> expirationTime 本次自动登录的有效期，key 为指定的一个散列盐值，用于防止令牌被修改。Security 先用base64解码获得用户名、过期时间和加密散列值；然后使用用户名获取密码；接着重新以该散列算法正向计算，并将计算结果与旧的加密散列值进行对比，从而确认该令牌是否失效

```java
public abstract class AbstractRememberMeServices implements RememberMeServices,
      InitializingBean, LogoutHandler {
   // ~ Static fields/initializers
   // =====================================================================================

   public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "remember-me";
   public static final String DEFAULT_PARAMETER = "remember-me";
   public static final int TWO_WEEKS_S = 1209600;

   private static final String DELIMITER = ":";

   // ~ Instance fields
   // ================================================================================================
   protected final Log logger = LogFactory.getLog(getClass());

   protected final MessageSourceAccessor messages = SpringSecurityMessageSource
         .getAccessor();

   private UserDetailsService userDetailsService;
   private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
   private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

   private String cookieName = SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;
   private String cookieDomain;
   private String parameter = DEFAULT_PARAMETER;
   private boolean alwaysRemember;
   private String key;
        // 默认过期时间 2个星期
   private int tokenValiditySeconds = TWO_WEEKS_S;
 }
```

```java
public class TokenBasedRememberMeServices extends AbstractRememberMeServices {

    // 散列加密部分
	protected String makeTokenSignature(long tokenExpiryTime, String username,
			String password) {
		String data = username + ":" + tokenExpiryTime + ":" + password + ":" + getKey();
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No MD5 algorithm available!");
		}

		return new String(Hex.encode(digest.digest(data.getBytes())));
	}
}
```

##### 会话管理

> 会话固定攻击、会话超时检测以及会话并发控制（一个账户是否能多处同时登录）

> 会话就是无状态的HTTP实现用户状态可维持的一种解决方案。HTTP本身的无状态使得用户在与服务器的交互过程中，每个请求之间都没有关联性。当用户首次访问系统时候，系统为该用户生成一个sessionId，并添加到cookie中。在用户的会话期内，每个请求都自动携带该cookie，因此系统可以很轻易地识别出这是来自哪个用户的请求。

> cookie被禁用，URL重写  http://www.baidu.com;jsessionid=xxx

1. 会话固定攻击

   > 黑客只需访问一次系统，将系统生成的sessionId提取并拼接到URL上，然后将该URL发给一些取得信任的用户。只要用户在session有效期内通过此URL进行的登录，该sessionId就会绑定到用户的身份，黑客便可以轻松享受同样的会话状态，完全不用用户名和密码

2. sessionManagement是一个会话管理的配置器，防御会话攻击的策略，默认是 migrateSession，StrictHttpFirewall会拦截非法请求

   - none  		不做任何变动，登录之后沿用旧的session
   - newSession   登录之后创建一个新的 session 
   - migrateSession  登录之后创建一个新的session，并将旧的session中的数据复制过来
   - changeSessionId  不创建新的会话，而是使用Servlet容器提供的会话固定保护

3.  会话并发控制问题

   > 首先尝试将已经登录的旧会话注销（访问/logout）,理论上应该可以继续登录，但是 spring security 依然提示我们超过了最大会话数目。事实上，除非重启服务；否则用户很难将再次登录系统。这是应为 spring security 是通过监听 session 的销毁时间来触发会话信息表相关的清理工作的，但是我们并没有注册过相关的监听器，导致spring security 无法正常清理过期或者已经注销的会话

```java
public class SessionRegistryImpl implements SessionRegistry,
		ApplicationListener<SessionDestroyedEvent> {
	
	// principal自己编写的实体，必须要重写 hashCode和equals,否则session并发控制会不起作用，还会引发内存泄漏
	/** <principal:Object,SessionIdSet> */
	private final ConcurrentMap<Object, Set<String>> principals;
	/** <sessionId:Object,SessionInformation> */
	private final Map<String, SessionInformation> sessionIds;
}
```

4. 集群会话的解决方案

   - session 保持  

     > 粘滞会话（sticky sessions），通常采用IP hash负载均衡策略将来自相同客户端的请求转发至相同的服务器上处理。存在一些缺陷。例如，某个营业部的网络使用相同IP出口，那么这个营业部所有的请求都将被转发到相同的服务器上，存在一定程度上的负载失衡

   - session 复制

     > 在集群服务器之间同步session数据，非常不可取

   - session 共享

     > 将 session 从服务器内存中抽离出来，集中存储到独立的数据容器，并由各个服务器共享。读写性能，稳定性以及网络IO都可能成为性能瓶颈。高可用部署的redis服务器为最优选择