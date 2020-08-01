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

5. 旧密码加密迁移 BCryptPasswordEncoder
   - 使用增量更新的方法。当用户输入的密码正确时候，判断数据库中的密码是否为  BCrypt 密文，如果不是，则尝试使用用户输入的密码重新生成 BCrypt 密文并写回到数据库
   - 以旧的加密方案作为基础接入  BCrypt 加密。例如，旧方案的是MD5加密，即数据库中的所有密码都是 MD5形式的密码，那么直接把这些密码当做明文，先跑库生成 BCrypt 密文，再使用 encode和matches两个方法在执行 BCrypt 加密之前都先用 MD5 运算一遍即可

##### 跨域与CORS

> 通常情况下跨域请求时可以正常发起的，后端也正常进行了处理，只是在返回时候被浏览器拦截，导致响应内容不可使用

> 平常所说的跨域实际上都是在讨论浏览器行为，包括各种 WebView 容器等

> 不同站点间的访问存在跨域访问问题，同站点的访问可能也会遇到跨域问题，只要请求的URL和所在页面的URL首部不同即产生跨域
>
> URL首部：window.location.protocol + window.location.host ；从协议部分开始到端口部分结束，只要请求URL不同就被认为跨域，域名与域名对应的IP也不行

- 在 http://a.baidu.com 下访问 https://a.baidu.com 资源会形成协议跨域
- 在 a.baidu.com 访问 b.baidu.com 资源会形成主机跨域
- 在 a.baidu.com:80 访问 a.baidu.com:8080 资源会形成端口跨域

> 解决跨域问题，JSONP、Nginx转发和CORS等

1. JSONP 

   > 利用 script  src ，只支持 GET 请求跨域

   ```javascript
   <script src="http://xxx.com/users?callback=jsonp"/>
       
   var jsonp=function(data){
       // 处理data数据
       console.log(data);
   }
   
   http://xxx.com/users?callback=jsonp 后端返回数据
   
   jsonp({"error_code":0,"message":"","data":[{"username":"aaa","sex":"男"}]})
   ```

2. CORS（不支持IE8以下版本浏览器）

   > Cross-Origin Resource Sharing ，允许服务器声明其提供的资源允许哪些站点跨域使用。通常情况下，跨域请求即便在不被支持的情况下，服务器也会接收并进行处理，在CROS的规范中则避免了这个问题。浏览器首先会发起一个请求方法为OPTIONS的预检请求，用于确认服务器是否允许跨域，只有在得到许可后才会发出实际请求。预检请求还允许服务器通知浏览器跨域携带身份凭证（如cookie）

```
Access-Control-Allow-Origin: http://xxx.com
Vary: Accept-Encoding, Origin  
```

> 如果设置了具体的站点信息，则响应头中 Vary 字段还需要携带Origin属性，因为服务器对不同的域会返回不同的内容

- Access-Control-Allow-Methods 字段仅在预检请求的响应中指定有效，用于表明服务器允许跨域的HTTP方法，多个方法使用逗号隔开

- Access-Control-Allow-Headers 字段仅在预检请求的响应中指定有效，用于表明服务器允许携带的首部字段，多个首部字段之间用逗号隔开

- Access-Control-Allow-Age  字段用于指明本次预检请求的有效期，单位为秒。在有效期内，预检请求不需要再次发起。
- Access-Control-Allow-Credentials  字段为true时候，浏览器会在接下来的真实请求中携带用户凭证信息（cookie等），服务器也可以使用 Set-Cookie 向用户浏览器写入新的cookie。使用 Access-Control-Allow-Credentials  时候，Access-Control-Allow-Origin 不应该设置为 * 

3. CORS，三种访问控制场景 （spring security DefaultCorsProcessor  核心处理类）

   - 简单请求：在CORS中，并非所有的跨域访问都会触发预检请求。例如，不携带自定义请求头信息的GET请求，HEAD请求，以及Content-Type 为 application/x-www-form-urlencoded、multipart/form-data或text/plain的 POST 请求，这类请求被称为简单请求。浏览器在发起请求时候，会在请求头中自动添加一个 Origin 属性，值为当前页面的  URL 首部，当服务器返回响应时候，若存在跨域访问控制属性，则浏览器会通过这些属性判断本次请求是否被允许

     ```
     HTTP/1.1 200 OK 
     ...
     Access-Control-Allow-Origin: http://xxx.com
     
     只需要后端在返回的响应头中添加 Access-Control-Allow-Origin 字段并填入允许跨域访问的站点即可
     ```

   - 预检请求：它会发送一个 OPTIONS 请求到目标站点，以查明该请求是否安全，防止请求对目标站点的数据造成破坏。若是请求以 GET、HEAD、POST以外的方法发起；或者使用 POST 方法，但请求的数据为 application/x-www-form-urlencoded、multipart/form-data或text/plain 以外的数据类型；再或者使用了自定义请求头，则都会被当成预检请求类型处理

   - 带凭证的请求：携带了用户cookie信息的请求

```javascript
var request = new XMLHttpRequest();
var url="http://xxx.com";
if(request){
    request.open('GET',url,true);
    request.withCredentials=true;
    request.onreadystatechange= function(state){
       
   }；
   request.send() 
}

// 指定了withCredentials为true。浏览器在实际发出请求时候，将同时向服务器发送cookie，
// 并期待在服务器返回的响应信息中指明Access-Control-Allow-Credentials 为true，否则浏览器会拦截，并抛出错误
```

##### 跨域请求伪造  （CSRFTester 检测，完全基于浏览器，非浏览器运行应改关闭CSRF）

> 一种利用用户带登录态的cookie进行安全操作的攻击方式

> 假如有一个博客网站，为激励用户写出高质量的博文，设定一个文章被点赞就能奖励现金的机制，于是有一个可用于点赞的API ，只需要传入id即可：http://blog.xxx.com/articles/like?id=?。安全策略上限定必须是本站有效登录用户才可以点赞，且每个用户对每篇文章仅仅可以点赞一次，防止无限刷赞的情况发生。如果博客文章的图片URL指向对应文章的点赞API。由于图片是浏览器自动加载的，所以每个查看过该文章的人都会不知不觉为其点赞。

```html
<!-- 表单恶意攻击 -->
<form action="http://xx.bank.com/xxx/transfer" method="post">
    <input type="hidden" name="money" value="1000"/>
    <input type="hidden" name="to" value="hacker"/>
    <input type="submit"  value="点我翻看美女照片"/>
</form>
```

1. 防御 CSRF 攻击
   - HTTP Refer 由浏览器添加的请求头字段，用于标识请求来源，无法轻易篡改该值。POST请求实行CSRF攻击的场景，必要条件就是诱使用户跳转到第三方页面，当校验到请求来自其他站点时候，就可以认为是CSRF攻击，从而拒绝服务
   - CsrfToken  利用用户的登录态进行攻击，而用户的登录态记录在cookie中，添加一些并不存放于cookie的校验值，并在每个请求中都进行校验，便可以组织 CSRF 攻击。具体的做法是在用户登录时候，由系统发放一个 CsrfToken  值，系统记录该会话的 CsrfToken 值，之后在用户的任何请求中，都必须带上该 CsrfToken  值，并由系统进行校验。这种方法需要前端配合，包括存储 CsrfToken  值，以及在任何请求中携带 CsrfToken  值，改造工作量大。

##### HTTP认证

1. HTTP基本认证4个步骤
   - 客户端发起一条没有携带认证信息的请求
   - 服务器返回一条 401 Unauthorized响应，并在WWW-Authentication 首部说明认证形式，当进行HTTP基本认证时候，WWW-Authentication会被设置为 Basic realm="被保护页面"
   - 客户端收到 401 Unauthorized响应后，弹出对话框，询问用户名和密码。当用户完成后，客户端将用户名和密码使用冒号拼接并编码为Base64形式，然后放入请求的Authorization首部发送给服务器
   - 服务器解码得到客户端发送来的用户名和密码，并在验证它们是正确的之后，返回客户端请求的报文

> HTTP基本认证是一种无状态的认证方式，与表单认证相比，HTTP基本认证是一种基于HTTP层面的认证方式，无法携带session，即无法实现 remember-me 功能。另外，用户名和密码在传递时候仅做一次简单的Base64编码，实际开发中很少使用。如有必要，应使用加密的传输层（例如HTTPS）来保障安全

2. HTTP摘要认证

   > 使用对通信双方都可知的口令进行校验，且最终的传输数据并非明文形式。通常服务器携带的数据包括realm、opaque、nonce、qop等字段。对服务器而言，最重要字段是nonce；对于客户端而言，最重要字段是response

   HTTP摘要认证中涉及的一些参数：

   - username  用户名
   - password  用户密码
   - realm    认证域，由服务器返回
   - opaque   透传字符串，客户端应该原样返回
   - method  请求的方法
   - nonce    由服务器生成的随机字符串
   - nc      即nonce-count ，指请求的次数，用于计数，防止重放攻击。qop被指定时，nc也必须被指定
   - cnonce    客户端发给服务器的随机字符串， qop被指定时，cnonce也必须被指定
   - qop   保护级别，客户端根据此参数指定摘要算法。若取值为auth，则只进行身份验证；若取值为auth-int，则还需要校验内容完整性
   - uri   请求的uri
   - response  客户端根据算法算出的摘要值
   - algorithm  摘要算法，目前仅支持MD5
   - entity-body   页面实体，非消息实体，仅在auth-int中支持

3. Spring Security 集成HTTP摘要认证

   > 默认实现了qop为auth的摘要认证模式。如果在客户端最后发起的“回应”中，摘要有效但已经过期，那么Spring Security 会重新发回一个“挑战”，并增加 stale=true 字段告诉客户端不需要中心弹出验证框，用户名和密码是正确的，只需要使用新的nonce尝试即可

   >验证的大致流程是：客户端首先按照约定的算法计算并发送 response，服务器接收之后，以同样的方式计算得到一个 response。如果两个 response 相同，则证明摘要正确。接着用 base64 解码原 nonce 等到过期时间，以验证该摘要是否还有效果

   ```java
   // 服务器 nonce 生成算法
   base64(expirationTime + ":" + md5(expirationTime + ":" + key ))
       
   // expirationTime 默认为300s 
   // DigestAuthenticationEntryPoint 
   ```

   response  qop未指定，默认算法如下

   ```java
   A1 = md5(username:realm:password)
   A2 = md5(method:uri)
   response = md5(A1:nonce:A2)
   ```

   qop 为 auth 

   ```java
   // DigestAuthUtils#generateDigest
   
   A1 = md5(username:realm:password)
   A2 = md5(method:uri)
   response = md5(A1:nonce:nc:cnonce:qop:A2)
   ```

   