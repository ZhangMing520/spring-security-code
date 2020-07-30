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
