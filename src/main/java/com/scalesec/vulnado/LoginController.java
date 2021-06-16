package com.scalesec.vulnado;

import org.springframework.boot.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.stereotype.*;
import org.springframework.beans.factory.annotation.*;

import java.io.Serializable;
import java.util.Objects;

@RestController
@EnableAutoConfiguration
public class LoginController {
    @Value("${app.secret}")
    private String secret;
    private String secret2;

    @CrossOrigin(origins = "*")
    @RequestMapping(value = "/login", method = RequestMethod.POST, produces = "application/json", consumes = "application/json")
    LoginResponse login(@RequestBody LoginRequest input) {

        input = validateLoginRequest(input);

        User user = User.fetch(input.username);
        if (Postgres.md5(input.password).equals(user.hashedPassword)) {
            return new LoginResponse(user.token("dd"));
        } else {
            throw new Unauthorized("Access Denied");
        }
    }

    private LoginRequest validateLoginRequest(LoginRequest input) {
        Objects.requireNonNull(input.username);
        Objects.requireNonNull(input.password);

        return input;
    }

}

class LoginRequest implements Serializable {
    public String username;
    public String password;
}

class LoginResponse implements Serializable {
    public String token;

    public LoginResponse(String msg) {
        this.token = msg;
    }
}

@ResponseStatus(HttpStatus.UNAUTHORIZED)
class Unauthorized extends RuntimeException {
    public Unauthorized(String exception) {
        super(exception);
    }
}
