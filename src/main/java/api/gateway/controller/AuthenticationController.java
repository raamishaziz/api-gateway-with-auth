package api.gateway.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import api.gateway.exceptions.CustomException;
import api.gateway.security.dto.AuthenticationRequest;
import api.gateway.security.dto.AuthenticationResponse;
import api.gateway.security.service.AuthenticationService;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  @Autowired
  private AuthenticationService service;

  
  @CrossOrigin(origins = "*")
  @PostMapping(value = "/authenticate", produces = "application/json")
  public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
    AuthenticationResponse resp;
    try {
      resp = service.authenticate(request);
    } catch (BadCredentialsException e) {
      throw new CustomException("Bad Credentials", "Bad Credentials", HttpStatus.UNAUTHORIZED.value(),
          HttpStatus.UNAUTHORIZED);
    } catch (UsernameNotFoundException e) {
      throw new CustomException("Invalid email/password provided", "User not found", HttpStatus.UNAUTHORIZED.value(),
          HttpStatus.UNAUTHORIZED);
    } catch (Exception e) {
      throw new CustomException("Unauthorized User.", "Could not authenticate user", HttpStatus.UNAUTHORIZED.value(),
          HttpStatus.UNAUTHORIZED);
    }
    return ResponseEntity.ok(resp);
  }
}
