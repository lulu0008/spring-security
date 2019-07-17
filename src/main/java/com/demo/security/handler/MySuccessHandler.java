package com.demo.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.demo.security.model.JwtUser;
import com.demo.security.utils.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 登录成功
 */
@Component
public class MySuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(MySuccessHandler.class);

    /**Json转化工具*/
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        JwtUser userDetails = (JwtUser)authentication.getPrincipal();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //生成token
        String token = JwtTokenUtil.generateToken(userDetails);
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_OK));
        map.put("msg", "登录成功");
        map.put("token", token);
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(map));
        writer.flush();
        writer.close();
    }
}
