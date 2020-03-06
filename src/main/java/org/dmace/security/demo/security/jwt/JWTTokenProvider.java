package org.dmace.security.demo.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.dmace.security.demo.model.security.UserEntity;
import org.dmace.security.demo.model.security.UserRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JWTTokenProvider {
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String TOKEN_TYPE = "JWT";

    @Value("${jwt.secret:Nh6jdqNHg33HX3Y6nnnw5bGVoAJ7YFdvBWjyPJnFjVeh4AnDCbuUA4EqyzAWuHBq}")
    private String jwtSecret;

    @Value("${jwt.token-expiration:86400}")
    private int jwtDurationSeconds;

    public String generateToken(final Authentication authentication) {

        UserEntity user = (UserEntity) authentication.getPrincipal();

        Date tokenExpirationDate = new Date(System.currentTimeMillis() + (jwtDurationSeconds * 1000));

        return Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes()), SignatureAlgorithm.HS512)
                .setHeaderParam("typ", TOKEN_TYPE)
                .setSubject(Long.toString(user.getId()))
                .setIssuedAt(new Date())
                .setExpiration(tokenExpirationDate)
                .claim("fullname", user.getFullName())
                .claim("roles", user.getRoles().stream()
                        .map(UserRole::name)
                        .collect(Collectors.joining(", "))
                )
                .compact();
    }

    public Long getUserIdFromJWT(final String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
				.build()
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }


	public boolean validateToken(final String authToken) {

		try {
			Jwts.parserBuilder()
					.setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
					.build()
					.parseClaimsJws(authToken);
			return true;
		} catch (SecurityException ex) {
			log.info("Invalid signature: " + ex.getMessage());
		} catch (MalformedJwtException ex) {
			log.info("malformed token: " + ex.getMessage());
		} catch (ExpiredJwtException ex) {
			log.info("Expired tocken: " + ex.getMessage());
		} catch (UnsupportedJwtException ex) {
			log.info("unsupported token: " + ex.getMessage());
		} catch (IllegalArgumentException ex) {
			log.info("empty JWT claims");
		}
        return false;
	}

}
