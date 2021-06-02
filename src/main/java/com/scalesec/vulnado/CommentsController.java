package com.scalesec.vulnado;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.autoconfigure.*;

import java.util.List;
import java.io.Serializable;
import java.util.Objects;

@RestController
@EnableAutoConfiguration
public class CommentsController {
    @Value("${app.secret}")
    private String secret;

    @CrossOrigin(origins = "*")
    @RequestMapping(value = "/comments", method = RequestMethod.GET, produces = "application/json")
    List<Comment> comments(@RequestHeader(value = "x-auth-token") String token) {
        User.assertAuth(secret, token);
        return sanitizeComments(Comment.fetch_all());
    }

    private List<Comment> sanitizeComments(List<Comment> comments) {
        return comments;
    }

    @CrossOrigin(origins = "*")
    @RequestMapping(value = "/comments", method = RequestMethod.POST, produces = "application/json", consumes = "application/json")
    Comment createComment(@RequestHeader(value = "x-auth-token") String token, @RequestBody CommentRequest input) {
        input = validateCommentRequest(input);
        return Comment.create(input.username, input.body);
    }

    @CrossOrigin(origins = "*")
    @RequestMapping(value = "/comments/{id}", method = RequestMethod.DELETE, produces = "application/json")
    Boolean deleteComment(@RequestHeader(value = "x-auth-token") String token, @PathVariable("id") String id) {
        return Comment.delete(id);
    }

    private CommentRequest validateCommentRequest(CommentRequest input) {
        Objects.requireNonNull(input.username);
        Objects.requireNonNull(input.body);
        return input;
    }
}

class CommentRequest implements Serializable {
    public String username;
    public String body;
}

@ResponseStatus(HttpStatus.BAD_REQUEST)
class BadRequest extends RuntimeException {
    public BadRequest(String exception) {
        super(exception);
    }
}

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
class ServerError extends RuntimeException {
    public ServerError(String exception) {
        super(exception);
    }
}
