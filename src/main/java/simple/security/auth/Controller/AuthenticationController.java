package simple.security.auth.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import simple.security.auth.Entity.UserEntity;
import simple.security.auth.Model.UserApp;
import simple.security.auth.Service.AuthenticationService;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserApp body) {
        try {
            UserEntity savedUser = authenticationService.registerUser(body);

            if(savedUser == null || savedUser.getUserID() == 0) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("User registration failed!");
            }

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("User has been registered!");
        } catch (Exception exp) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error has occured!");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody UserApp body) {
        try {
            Authentication auth = authenticationService.authenticate(
                    new UsernamePasswordAuthenticationToken(body.getUsername(), body.getPassword())
            );

            if(auth.isAuthenticated()) {
                HttpHeaders headers = new HttpHeaders();
                headers.add("Location", "/user");
                return new ResponseEntity<>(headers, HttpStatus.FOUND);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Login has failed!");
            }
        } catch (Exception exp) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");
        }
    }
}
