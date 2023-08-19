package ma.sir.ged.zynerator.security.dao;


import ma.sir.ged.zynerator.security.bean.UserS;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserS, Long> {
  Optional<UserS> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
