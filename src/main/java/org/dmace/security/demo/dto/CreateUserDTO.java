package org.dmace.security.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

@Data
@NoArgsConstructor @AllArgsConstructor
@Builder
public class CreateUserDTO {

    @NotEmpty
    @Size(min = 3, max = 64)
    private String username;

    @NotEmpty
    @Size(min = 6, max = 64)
    private String password;

    @NotEmpty
    @Size(min = 6, max = 64)
    private String passwordRepeat;

    private String avatar;
}
