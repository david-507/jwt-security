package org.dmace.security.demo.service;

import lombok.RequiredArgsConstructor;
import org.dmace.security.demo.dto.CreateUserDTO;
import org.dmace.security.demo.errors.exceptions.NoMatchingPasswordsException;
import org.dmace.security.demo.model.security.UserEntity;
import org.dmace.security.demo.model.security.UserRole;
import org.dmace.security.demo.repo.UserRepo;
import org.dmace.security.demo.service.base.BaseService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class UserService extends BaseService<UserEntity, Long, UserRepo> {

    private final PasswordEncoder encoder;

    Optional<UserEntity> findByUsername(final String username) {
        return this.repository.findByUsername(username);
    }

    public UserEntity createUser(final CreateUserDTO dto) {

        if( dto.getPassword().contentEquals(dto.getPasswordRepeat()) ) {
            UserEntity entity = UserEntity.builder()
                    .username(dto.getUsername())
                    .password(encoder.encode(dto.getPassword()))
                    .avatar(dto.getAvatar())
                    .roles(Stream.of(UserRole.USER).collect(Collectors.toSet()))
                    // Set.of(UserRole.USER); <- java 9 !!
                    .build();

            try {
                return save(entity);
            } catch (DataIntegrityViolationException ex) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, " username already exists");
            }
        } else {
            throw new NoMatchingPasswordsException();
        }
    }

}
