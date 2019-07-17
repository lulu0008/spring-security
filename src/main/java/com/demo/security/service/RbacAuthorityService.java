package com.demo.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Service("rbacauthorityservice")
public class RbacAuthorityService {

//    @Autowired
//    private SysResourceMapper sysResourceMapper;

    /**
     * 自定义权限信息
     */
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        //return new UsernamePasswordAuthenticationToken(userInfo, password, userInfo.getAuthorities());
        //得到的principal的信息是用户名还是整个用户信息取决于在SelfAuthenticationProvider中传参的方式
        Object userInfo = authentication.getPrincipal();
        boolean hasPermission = false;
        if (userInfo instanceof UserDetails) {
            String username = ((UserDetails) userInfo).getUsername();
            //这里不做数据库菜单路径的交互
            List<String> list = new ArrayList<>();
            list.add("/index");
            list.add("/system");
            list.add("/user");
            //自定义验证规则
            //获取当前用户的权限菜单，和请求的菜单路径做匹配
            for (int i = 0; i < list.size(); i++) {
               String role = "/api/v*" + list.get(i) + "/**";
               AntPathMatcher antPathMatcher = new AntPathMatcher();
                if (antPathMatcher.match(role, request.getRequestURI())) {
                    hasPermission = true;
                    break;
                }
            }
            return hasPermission;
        }
        return hasPermission;
    }

}
