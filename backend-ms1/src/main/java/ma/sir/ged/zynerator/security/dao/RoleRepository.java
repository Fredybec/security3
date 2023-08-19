package ma.sir.ged.zynerator.security.dao;


import ma.sir.ged.zynerator.security.bean.ERole;
import ma.sir.ged.zynerator.security.bean.RoleS;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleS, Long> {
  Optional<RoleS> findByName(ERole name);
}
