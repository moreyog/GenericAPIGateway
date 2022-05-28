package com.s3.apigateway.security;

import javax.ws.rs.core.HttpHeaders;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config>{

	public AuthorizationFilter()
	{
		super(Config.class);
	}
	public static class Config {
		
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange,chain)->{
			
			ServerHttpRequest request = exchange.getRequest();
			if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange,"No authorization header",HttpStatus.UNAUTHORIZED);
			}
			
			String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer ", "");
			
			if(!isJwtValid(jwt))
			{
				return onError(exchange,"Jwt token is not valid",HttpStatus.UNAUTHORIZED);
			}
			
			return chain.filter(exchange);
		};
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {

		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		
		return response.setComplete();
	}
	
	private boolean isJwtValid(String jwt) {
		boolean isValidToken = true;
		
		String subject = Jwts.parser()
				.setSigningKey("asd234sdf6s8sdf7as7d")
				.parseClaimsJws(jwt)
				.getBody()
				.getSubject();
		
		if(subject == null || subject.isEmpty())
			return false;
		
		return isValidToken;
	}
}
