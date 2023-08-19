package ma.sir.ged.dao.facade.core;

import org.springframework.data.jpa.repository.Query;
import ma.sir.ged.zynerator.repository.AbstractRepository;
import ma.sir.ged.bean.core.Utilisateur;
import org.springframework.stereotype.Repository;
import ma.sir.ged.bean.core.Utilisateur;
import java.util.List;


@Repository
public interface UtilisateurDao extends AbstractRepository<Utilisateur,Long>  {
    Utilisateur findByEmail(String email);
    int deleteByEmail(String email);

    List<Utilisateur> findByGenderId(Long id);
    int deleteByGenderId(Long id);

    @Query("SELECT NEW Utilisateur(item.id,item.nom) FROM Utilisateur item")
    List<Utilisateur> findAllOptimized();
}
