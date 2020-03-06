package org.dmace.security.demo.controller.login;

import lombok.RequiredArgsConstructor;
import org.dmace.security.demo.dto.GetUserDTO;
import org.dmace.security.demo.dto.UserDtoConverter;
import org.dmace.security.demo.model.login.JwtUserResponse;
import org.dmace.security.demo.model.login.LoginRequest;
import org.dmace.security.demo.model.security.UserEntity;
import org.dmace.security.demo.model.security.UserRole;
import org.dmace.security.demo.security.jwt.JWTTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {
	
	private final AuthenticationManager authenticationManager;
	private final JWTTokenProvider tokenProvider;
	private final UserDtoConverter converter;
	
	@PostMapping("/auth/login")
	public ResponseEntity<JwtUserResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication =
				authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(
							loginRequest.getUsername(),
							loginRequest.getPassword()
						)							
				);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		UserEntity user = (UserEntity) authentication.getPrincipal();
		String jwtToken = tokenProvider.generateToken(authentication);

		return ResponseEntity.status(HttpStatus.CREATED).body(
				convertUserEntityAndTokenToJwtUserResponse(user, jwtToken)
		);
	}
	
	@PreAuthorize("isAuthenticated()")
	@GetMapping("/user/me")
	public GetUserDTO me(@AuthenticationPrincipal UserEntity user) {
		return converter.convert(user);
	}
	
	private JwtUserResponse convertUserEntityAndTokenToJwtUserResponse(UserEntity user, String jwtToken) {
		return JwtUserResponse
				.jwtUserResponseBuilder()
				.email(user.getEmail())
				.username(user.getUsername())
				.avatar(user.getAvatar())
				.roles(user.getRoles().stream().map(UserRole::name).collect(Collectors.toSet()))
				.token(jwtToken)
				.build();
		
	}

}