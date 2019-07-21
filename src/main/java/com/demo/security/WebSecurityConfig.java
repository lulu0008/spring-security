package com.demo.security;

import com.demo.security.filter.JwtAuthenticationProvider;
import com.demo.security.filter.JwtAuthenticationTokenFilter;
import com.demo.security.filter.MyUsernamePasswordAuthenticationFilter;
import com.demo.security.handler.*;
import com.demo.security.service.JwtUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsUtils;

import javax.annotation.Resource;

/**
 * 权限配置中心
 */
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)//是否支持web
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyAuthenticationEntryPoint myAuthenticationEntryPoint;//未登陆时返回 JSON 格式的数据给前端（否则为 html）

    @Resource
    private MySuccessHandler mySuccessHandler;//自定义的登录成功处理器

    @Resource
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler; //自定义的登录失败处理器

    @Resource
    private MyLogoutSuccessHandler myLogoutSuccessHandler; //依赖注入自定义的注销成功的处理器

    @Resource
    private MyAccessDeniedHandler myAccessDeniedHandler;//注册没有权限的处理器

    @Resource
    private JwtUserDetailsService jwtUserDetailsService; //自定义user

    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter; // 拦截token JWT 拦截器

    @Resource
    private JwtAuthenticationProvider jwtAuthenticationProvider; // 自定义登录

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //这里可启用我们自己的登陆验证逻辑,用户密码加密 放到jwtAuthenticationProvider中
        //auth.userDetailsService(jwtUserDetailsService).passwordEncoder(new BCryptPasswordEncoder());
        auth.authenticationProvider(jwtAuthenticationProvider);
    }

    /**
     * 配置spring security的控制逻辑
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        String[] arrUrl = JwtAuthenticationTokenFilter.arrUrl;

        // 新加入(cors) CSRF  取消跨站请求伪造防护
        http.cors().and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 使用 JWT，关闭token

        //用户未登录
        http.httpBasic().authenticationEntryPoint(myAuthenticationEntryPoint);

        http.authorizeRequests()
                    /** 设置任何用户可以访问的路径 **/
                    .antMatchers(arrUrl).permitAll()
                    /** 解决跨域 **/
                    .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()

                    /** 任何尚未匹配的URL都只需要对用户进行身份验证  每个请求的url必须通过这个规则  RBAC 动态 url 认证 **/
                    .anyRequest().access("@rbacauthorityservice.hasPermission(request,authentication)")

                /**表单登录开始配置     表单登录使用的配置  不使用暂时注释 **/
//                    .and()
//                    .formLogin() //开启登录, 定义当需要用户登录时候，转到的登录页面
//                        .loginProcessingUrl("/user/login")//loginProcessingUrl用于指定前后端分离的时候调用后台登录接口的名称
//                        .successHandler(mySuccessHandler) // 登录成功
//                        .failureHandler(myAuthenticationFailureHandler) // 登录失败
                /**表单登录结束配置     */

                    .and()
                    /** loginProcessingUrl用于指定前后端分离的时候调用后台注销接口的名称 如果启用了CSRF保护(默认)，那么请求也必须是POST **/
                    .logout()
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(myLogoutSuccessHandler)
                        .permitAll();

        // 无权访问 JSON 格式的数据
        http.exceptionHandling().accessDeniedHandler(myAccessDeniedHandler);

        //在执行MyUsernamePasswordAuthenticationFilter之前执行jwtAuthenticationTokenFilter
        http.addFilterBefore(jwtAuthenticationTokenFilter, MyUsernamePasswordAuthenticationFilter.class);
        
        //用重写的Filter替换掉原有的UsernamePasswordAuthenticationFilter
        http.addFilterAt(customAuthenticationFilter(),UsernamePasswordAuthenticationFilter.class);

         // 禁用缓存
        http.headers().cacheControl();
    }


    /**
     *  JSON登陆（注册登录的bean）
     */
    @Bean
    MyUsernamePasswordAuthenticationFilter customAuthenticationFilter() throws Exception {
        MyUsernamePasswordAuthenticationFilter filter = new MyUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(mySuccessHandler);
        filter.setAuthenticationFailureHandler(myAuthenticationFailureHandler);
        filter.setFilterProcessesUrl("/user/login");
        //这句很关键，重用WebSecurityConfigurerAdapter配置的AuthenticationManager，不然要自己组装AuthenticationManager
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }
}
