package api.gateway.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import api.gateway.security.model.Token;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

  @Query(value = "select * from token where user_id = :id", nativeQuery = true)
  List<Token> findAllValidTokenByUser(Long id);

  Optional<Token> findByToken(String token);
}
