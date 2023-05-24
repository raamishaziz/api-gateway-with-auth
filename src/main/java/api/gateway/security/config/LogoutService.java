package api.gateway.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import api.gateway.security.model.Token;
import api.gateway.security.repository.TokenRepository;
import api.gateway.utils.Constants;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

  private final TokenRepository tokenRepository;

  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    final String authHeader = request.getHeader(Constants.AUTHORIZATION);
    final String jwt;
    if (Objects.isNull(authHeader) || !authHeader.startsWith(Constants.TOKEN_TYPE)) {
      return;
    }
    jwt = authHeader.substring(Constants.NUM_7);
    Token storedToken = tokenRepository.findByToken(jwt).orElse(null);
    if (null != storedToken) {
      storedToken.setExpired(true);
      storedToken.setRevoked(true);
      tokenRepository.save(storedToken);
      SecurityContextHolder.clearContext();
    }
  }
}
