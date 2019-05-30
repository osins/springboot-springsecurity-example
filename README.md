# Springboot-springsecurity-example
对于初次接触springboot的程序员，可能对于Springboot的安全验证比较陌生，本示例希望能够帮助各位快速掌握Spring security的配置和相关代码的编写。
Springboot-springsecurity-example 是一个springboot中应用springsecurity的例子，同时本示例自定义了用户名、密码、验证码的登录验证规则。

### Spring security重要的几个代码在security目录下，其中代码编写顺序如下：
#### 1、用户信息
创建一个继承自org.springframework.security.core.userdetails.UserDetails的类，该类实现了用户基本信息和登录验证相关的几个方法。

#### 2、数据连接
创建一个继承自org.springframework.security.core.userdetails.UserDetailsService的类，实现数据库中获取用户信息的功能代码。

#### 3、web数据获取
创建一个继承自org.springframework.security.web.authentication.WebAuthenticationDetails的类，实现web验证相关的验证详情来源。

#### 4、web提交登录数据来源绑定
创建一个继承自org.springframework.security.authentication.AuthenticationDetailsSource的类，实现web验证相关的来源。

#### 5、自定义登录逻辑
创建一个继承自org.springframework.security.authentication.AuthenticationProvider的类，实现用户登录验证服务，其中authenticate方法具体验证的方法，其中包括用户名、密码、验证码的比对。

#### 6、配置Spring security
创建一个继承自org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter的类，以实现Spring security的配置。

configure(HttpSecurity http) 方法实现了绑定自定义验证详情来源、登录和成功后的处理规则。
configure(AuthenticationManagerBuilder auth) 方法实现了绑定自定义验证的处理规则。

本例中验证码采用了Google的kaptcha，在DefaultController的login方法中初始化和保存验证码到Session，在继承自AuthenticationProvider的SAuthenticationProvider类中比对用户输入的验证码和session中保存的验证码是否一致。

BCryptPasswordEncoder是Springboot security中自带的一个用户密码加密工具，encode方法用来加密密码，matches方法用来比对用户登录时输入的密码和数据库中获取到的加密后的字符串是否匹配。
