package org.dmace.security.demo.controller;

import lombok.RequiredArgsConstructor;
import org.dmace.security.demo.dto.CreateUserDTO;
import org.dmace.security.demo.dto.GetUserDTO;
import org.dmace.security.demo.dto.UserDtoConverter;
import org.dmace.security.demo.model.security.UserEntity;
import org.dmace.security.demo.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService service;
    private final UserDtoConverter converter;

    @PostMapping("")
    public ResponseEntity<GetUserDTO> createUser(@RequestBody CreateUserDTO user) {
        return ResponseEntity.status(HttpStatus.CREATED).body( converter.convert(service.createUser(user)));
    }

    @GetMapping("/me")
    public ResponseEntity<GetUserDTO> me(@AuthenticationPrincipal UserEntity user) {
        return ResponseEntity.status(HttpStatus.OK).body( converter.convert(user));
    }
}
