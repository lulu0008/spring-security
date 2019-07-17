package com.demo.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.demo.security.model.JwtUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 注销登录
 */
@Component
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {

    /**Json转化工具*/
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        JwtUser userDetails = (JwtUser)authentication.getPrincipal();
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_OK));
        map.put("msg", "退出成功");
        map.put("username", userDetails.getUsername());
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        try {
            writer.write(objectMapper.writeValueAsString(map));
            writer.flush();
            writer.close();
        }catch (IOException o){
            o.printStackTrace();
            if(writer != null){
                writer.flush();
                writer.close();
            }
        }
    }
}
