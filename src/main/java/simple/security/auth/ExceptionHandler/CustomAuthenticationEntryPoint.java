package simple.security.auth.ExceptionHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException)
            throws IOException, ServletException {

        response.setHeader("eazybank-error-reason", "Authentication failed");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json:charset=UTF-8");

        String jsonResponseHeader = setCustomAuthenticationEntryPointValues(request, authException);
        response.getWriter().write(jsonResponseHeader);
    }

    private static String setCustomAuthenticationEntryPointValues(
            HttpServletRequest request,
            AuthenticationException authException) {

        LocalDateTime currentTimeStamp = LocalDateTime.now();
        String message = (
                authException != null && authException.getMessage() != null
        ) ? authException.getMessage() : "Unauthorized";

        return httpBodyResponse(
                currentTimeStamp,
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                message,
                request.getRequestURI()
        );
    }

    private static String httpBodyResponse(
            LocalDateTime currentTimeStamp,
            int status,
            String error,
            String message,
            String path) {
        String jsonResponseBody = String.format(
                "{" +
                        "\"timestamp\":\"%s\"," +
                        "\"status\":%d," +
                        "\"error\":\"%s\"," +
                        "\"message\":\"%s\"," +
                        "\"path\":\"%s\"" +
                        "}",
                currentTimeStamp,
                status,
                error,
                message,
                path
        );
        return jsonResponseBody;
    }
}
