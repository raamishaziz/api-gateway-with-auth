package api.gateway.security.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestHeader;

import api.gateway.security.config.JwtService;
import api.gateway.security.dto.AuthenticationRequest;
import api.gateway.security.dto.AuthenticationResponse;
import api.gateway.security.dto.RegisterRequest;
import api.gateway.security.model.User;
import api.gateway.security.repository.TokenRepository;
import api.gateway.security.repository.UserRepository;
import api.gateway.utils.Constants;

import java.security.SignatureException;
import java.util.Date;
import java.util.Objects;
import lombok.extern.log4j.Log4j2;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthenticationService {
  @Autowired
  private UserRepository repository;
  @Autowired
  private TokenRepository tokenRepository;
  @Autowired
  private PasswordEncoder passwordEncoder;
  @Autowired
  private JwtService jwtService;
  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  CustomUserDetailsService customUserDetailsService;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstName(request.getFirstName())
        .lastName(request.getLastName())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        // .userType(Role.MARKETER)
        .build();
    repository.save(user);
    // var jwtToken = jwtService.generateToken(user);
    // saveUserToken(savedUser, jwtToken);
    return AuthenticationResponse.builder().tokenType("Bearer")
        .build();
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) throws BadCredentialsException {
    String jwtToken = null;
    User user = null;
    try {
      log.info("Going to authenticate for requested user {}", request.getEmail());
      Authentication authentication = authenticationManager
          .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
      if (!authentication.isAuthenticated()) {
        log.error("Invalid credentials in request against email{}");
        throw new UsernameNotFoundException("INVALID_CREDENTIALS");
      }
      UserDetails userDetails = customUserDetailsService.loadUserByUsername(request.getEmail());
      log.info("User loaded successfully!");
      jwtToken = jwtService.generateToken(userDetails);
      log.info("jwt token generated successfully!");
      user = repository.findByEmail(request.getEmail());
      log.info("Going to revoke all valid previous tokens");
      revokeAllUserTokens(user);
      log.info("Going save token against user id {}", user.getId());
      saveUserToken(user, jwtToken);
      Date expDate = jwtService.extractExpiration(jwtToken);
      return AuthenticationResponse.builder()
          .user(mapUserDtoFromUserEntity(user))
          .accessToken(jwtToken)
          .tokenType(Constants.TOKEN_TYPE)
          .expiresAt(null != expDate ? String.valueOf(expDate) : null)
          .build();
    } catch (DisabledException e) {
      throw new DisabledException("USER_DISABLED", e);
    } catch (BadCredentialsException e) {
      throw new UsernameNotFoundException("INVALID_CREDENTIALS");
    } catch (Exception e) {
      throw new AuthenticationCredentialsNotFoundException("Authentication Failed!", e);
    }
  }

  public boolean validateToken(@RequestHeader("token") String token) throws SignatureException {
    final String jwt;
    final String userEmail;

    log.info("Going to validate token received in header..");
    final String authHeader = token;
    if (Objects.isNull(authHeader) || !authHeader.startsWith(Constants.TOKEN_TYPE)) {
      throw new UsernameNotFoundException("No Token found!");
    }

    try {
      jwt = authHeader.substring(Constants.NUM_7);
      log.info("Going to extract email from token.");
      userEmail = jwtService.extractUsername(jwt);
      if (userEmail != null) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEmail);
        boolean isTokenValid = tokenRepository.findByToken(jwt)
            .map(t -> !t.isExpired() && !t.isRevoked())
            .orElse(false);
        if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
          log.info("Token is validated.. now setting authentication in context");
          UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
              userDetails.getAuthorities());
          // authToken.setDetails(new
          // WebAuthenticationDetailsSource().buildDetails(null));
          SecurityContextHolder.getContext().setAuthentication(authToken);
          return true;
        }
      }
    } catch (SignatureException e) {
      throw new SignatureException("JWT signature does not match locally computed signature", e);
    } catch (ExpiredJwtException e) {
      throw new ExpiredJwtException(null, null, "Token expired");
    } catch (MalformedJwtException e) {
      throw new MalformedJwtException("Invalid JWT token.");
    } catch (UnsupportedJwtException e) {
      throw new MalformedJwtException("Unsupported JWT token");
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("JWT token compact of handler are invalid.");
    } catch (io.jsonwebtoken.security.SignatureException e) {
      throw new SignatureException("JWT signature does not match locally computed signature", e);
    }
    return false;
  }

  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .userId(user.getId())
        .token(jwtToken)
        .tokenType(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .build();
    tokenRepository.save(token);
  }

  private void revokeAllUserTokens(User user) {
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
    if (validUserTokens.isEmpty())
      return;
    validUserTokens.forEach(token -> {
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens);
  }

  private UserDto mapUserDtoFromUserEntity(User user) {
    UserDto userDto = new UserDto();
    userDto.setId(user.getId());
    userDto.setEmail(user.getEmail());
    userDto.setRole(user.getUserType());
    userDto.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
    userDto.setFirstName(user.getFirstName());
    userDto.setActive(user.getActive());
    return userDto;
  }
}
