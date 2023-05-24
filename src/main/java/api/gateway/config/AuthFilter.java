package api.gateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import api.gateway.exceptions.ErrorMessage;
import api.gateway.security.service.AuthenticationService;
import api.gateway.utils.Constants;
import reactor.core.publisher.Mono;
import lombok.extern.log4j.Log4j2;

import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

@Component
@Log4j2
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

    @Autowired
    private AuthenticationService service;

    // list down services here which need to be accessible without authentication
    private static final List<String> ACCESSIBLE_ENDPOINTS = Arrays.asList(
            "/api/v1/user/addUser",
            "/api/v1/user/activateUser"
    );



    public AuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if (shouldBypassAuthentication(request)) {
                log.info("Skipping authentication for accessible endpoint {}", request.getURI().getPath());
                return chain.filter(exchange);
            }
            if (!request.getHeaders().containsKey("Authorization")) {
                log.error("Authorization header is missing in request [Unauthorized request!]");
                return unauthorizedException(exchange, "No Authorization header present");
            }
            List<String> headerList = request.getHeaders().get(Constants.AUTHORIZATION);
            if (headerList == null) {
                log.error("Authorization header key is there but value is missing");
                return unauthorizedException(exchange, "No Authorization header value present");
            } else {
                String authHeader = headerList.get(0);
                String[] parts = authHeader.split(" ");
                if (parts.length != 2 || !Constants.TOKEN_TYPE.equals(parts[0].trim())) {
                    log.error("Bearer token either missing or wrong token structure [Unauthorized request!]");
                    return unauthorizedException(exchange, "Invalid auth token structure");
                }

                try {
                    if (!service.validateToken(authHeader)) {
                        log.error("Token not validated [Unauthorized request!]");
                        return unauthorizedException(exchange, "Invalid Token!");
                    }
                } catch (SignatureException e) {
                    log.error("Signature mismatched.", e);
                    return unauthorizedException(exchange, e.getMessage());
                } catch (ExpiredJwtException e) {
                    log.error("Jwt token expired.", e);
                    return unauthorizedException(exchange, e.getMessage());
                } catch (MalformedJwtException e) {
                    log.error("Invalid JWT token.", e);
                    return unauthorizedException(exchange, e.getMessage());
                } catch (UnsupportedJwtException e) {
                    log.error("Unsupported JWT token.", e);
                    return unauthorizedException(exchange, e.getMessage());
                } catch (IllegalArgumentException e) {
                    log.error("JWT token compact of handler are invalid.", e);
                    return unauthorizedException(exchange, e.getMessage());
                }

                log.info("Token validated successfully!, routing request to {}", request.getURI().getPath());
                return chain.filter(exchange);
            }
        };
    }

    public static class Config {
        // Put the configuration properties
    }

    private boolean shouldBypassAuthentication(ServerHttpRequest request) {
        String requestUri = request.getURI().getPath();
        for (String endpoint : ACCESSIBLE_ENDPOINTS) {
            if (requestUri.contains(endpoint)) {
                return true;
            }
        }
        return false;
    }

    private Mono<Void> unauthorizedException(ServerWebExchange exchange, String message) {
        ErrorMessage errorResponse = new ErrorMessage(HttpStatus.UNAUTHORIZED, message);
        return Mono.just(errorResponse)
                .flatMap(errorMessage -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                    try {
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                                .bufferFactory().wrap(new ObjectMapper().writeValueAsBytes(errorResponse))));
                    } catch (JsonProcessingException ex) {
                        throw new RuntimeException(ex);
                    }
                });
    }
}
