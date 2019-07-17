package com.demo.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.demo.security.service.JwtUserDetailsService;
import com.demo.security.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 确保经过filter为一次请求
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private final static String HEADER = "Authorization";
    private final static String BEARER = "Bearer ";
    public static String[] arrUrl = new String[]{"/user/login"};

    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        boolean boo = false;
        for(int i = 0; i < arrUrl.length; i++){
            if(antPathMatcher.match(arrUrl[i],request.getRequestURI())){
                boo = true;
                break;
            }
        }
        if(boo){
            chain.doFilter(request, response);
            return;
        }
        String header = request.getHeader(HEADER);
        if (header == null || !header.startsWith(BEARER)) {
            getResponse(response,"token不合法！");
            return;
        }
        final String authToken = header.substring(BEARER.length());
        if(JwtTokenUtil.isTokenExpired(authToken)){
            getResponse(response,"token过期！");
            return;
        }
        String username = jwtTokenUtil.getUsernameFromToken(authToken);
        if(username == null || username == ""){
            getResponse(response,"token错误！");
            return;
        }
        //把用户的信息填充到上下文中
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (userDetails != null) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        logger.info("checking authentication " + username);
        chain.doFilter(request, response);
    }

    /**
     *  组装token验证失败的返回
     * @param res
     * @param msg
     * @return
     */
    private HttpServletResponse getResponse(HttpServletResponse res,String msg){
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_FORBIDDEN));
        map.put("msg", msg);
        res.setContentType("Application/json;charset=UTF-8");
        Writer writer;
        try {
            writer = res.getWriter();
            writer.write(objectMapper.writeValueAsString(map));
            writer.flush();
            writer.close();
        }catch (Exception o){
            o.printStackTrace();
        }
        return res;
    }

}
