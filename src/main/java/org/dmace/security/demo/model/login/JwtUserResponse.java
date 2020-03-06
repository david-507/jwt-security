package org.dmace.security.demo.model.login;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.dmace.security.demo.dto.GetUserDTO;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
public class JwtUserResponse extends GetUserDTO {

    private String token;

    public JwtUserResponse(String token) {
        this.token = token;
    }

    @Builder(builderMethodName = "jwtUserResponseBuilder")
    public JwtUserResponse(String email, String username, String avatar, Set<String> roles, String token) {
        super(email, username, avatar, roles);
        this.token = token;
    }
}
