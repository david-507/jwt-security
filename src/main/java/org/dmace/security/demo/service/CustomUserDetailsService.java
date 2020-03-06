package org.dmace.security.demo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("userDetailsService")
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService service;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return service.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("not found"));
    }

    public UserDetails loadUserById(final Long id) {
        return service.findById(id).orElseThrow(() -> new UsernameNotFoundException("not found"));
    }
}
