package org.dmace.security.demo.dto;

import lombok.*;

import java.util.Set;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GetUserDTO {
    private String email;
    private String username;
    private String avatar;
    private Set<String> roles;
}
