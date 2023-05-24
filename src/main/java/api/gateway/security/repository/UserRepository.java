package api.gateway.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import api.gateway.security.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByEmail(String email);
}
