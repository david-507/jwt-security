package org.dmace.security.demo.dto;

import org.dmace.security.demo.model.security.UserEntity;
import org.dmace.security.demo.model.security.UserRole;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class UserDtoConverter {

    public GetUserDTO convert(UserEntity entity) {
        return GetUserDTO.builder()
                .avatar(entity.getAvatar())
                .username(entity.getUsername())
                .roles(entity.getRoles().stream().map(UserRole::name).collect(Collectors.toSet()))
                .build();
    }
}
