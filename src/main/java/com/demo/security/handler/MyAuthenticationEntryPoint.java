package com.demo.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 用户未登录时返回给前端的数据
 */
@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_CREATED));
        map.put("msg", e.getMessage());
        map.put("msg1", "用户未登录");
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
