package simple.security.auth.ExceptionHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        response.setHeader("eazybank-denied-reason", "Authorization Failed!");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json:charset=UTF-8");

        String jsonResponseHeader = setCustomAccessDeniedValues(request, accessDeniedException);
        response.getWriter().write(jsonResponseHeader);
    }

    private static String setCustomAccessDeniedValues(
            HttpServletRequest request,
            AccessDeniedException accessDeniedException) {

        LocalDateTime currentTimeStamp = LocalDateTime.now();
        String message = (accessDeniedException != null && accessDeniedException.getMessage() != null) ? accessDeniedException.getMessage() : "Unauthorized";

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
