package ma.sir.ged.dao.facade.core;

import org.springframework.data.jpa.repository.Query;
import ma.sir.ged.zynerator.repository.AbstractRepository;
import ma.sir.ged.bean.core.EtatUtilisateur;
import org.springframework.stereotype.Repository;
import ma.sir.ged.bean.core.EtatUtilisateur;
import java.util.List;


@Repository
public interface EtatUtilisateurDao extends AbstractRepository<EtatUtilisateur,Long>  {
    EtatUtilisateur findByCode(String code);
    int deleteByCode(String code);


    @Query("SELECT NEW EtatUtilisateur(item.id,item.libelle) FROM EtatUtilisateur item")
    List<EtatUtilisateur> findAllOptimized();
}
