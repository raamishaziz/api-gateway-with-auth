package api.gateway.security.service;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import api.gateway.security.model.User;
import api.gateway.security.repository.UserRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Log4j2
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository repo;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		List<GrantedAuthority> roles = new ArrayList<>();
		log.info("Going to retrieve user details for requested user {}", email);
		User user = repo.findByEmail(email);
		if (null == user) {
			log.info("user not found against email {}", email);
			throw new UsernameNotFoundException("No user found");
		}
		if (null != user.getUserType()) {
			roles = Arrays.stream(user.getUserType().split(","))
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList());
		}

		return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true,
				true, true, true, roles);
	}

	// private List<GrantedAuthority> getRoles(List<String> roles) {
	// List<GrantedAuthority> authorities = new ArrayList<>();
	// for (String role : roles) {
	// authorities.add(new SimpleGrantedAuthority(role));
	// }
	// return authorities;
	// }
}
