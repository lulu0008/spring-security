package com.demo.security.service;


import com.demo.security.model.JwtUser;
import com.demo.security.model.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;

/**
 *  查询用户关联角色信息
 */
@Component
public class JwtUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailsService.class);

//    @Autowired
//    private UserMapper userMapper;
//    @Autowired
//    private SysRoleMapper sysRoleMapper;
//    @Autowired
//    private SysUserRoleMapper sysUserRoleMapper;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //这里只是测试使用，暂时不跟数据库交互了
        UserModel user = new UserModel();
        user.setUsername(username);
        user.setPassword("admin");
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
        //此处将权限信息添加到 GrantedAuthority 对象中，在后面进行权限验证时会使用GrantedAuthority 对象。
        grantedAuthorities.add(grantedAuthority);
        JwtUser jwtUser = new JwtUser(user.getUsername(),user.getPassword(), grantedAuthorities);
        return jwtUser;
    }
}
