package org.dmace.security.demo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dmace.security.demo.errors.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

//@Component
public class CustomBasicAuthEntryPoint extends BasicAuthenticationEntryPoint {
    private static final String REALNAME = "david.com";
    private final ObjectMapper mapper;

    public CustomBasicAuthEntryPoint(final ObjectMapper mapper) {
        super();
        super.setRealmName(REALNAME);
        this.mapper = mapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        response.addHeader("WWW-Authenticate", "Basic realm=\"" + REALNAME + "\"");
        response.setContentType(APPLICATION_JSON_VALUE);
        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());

        ApiError error = new ApiError(HttpStatus.UNAUTHORIZED, authException.getMessage());
        String strApiError = mapper.writeValueAsString(error);

        response.getWriter().println(strApiError);
    }
}
