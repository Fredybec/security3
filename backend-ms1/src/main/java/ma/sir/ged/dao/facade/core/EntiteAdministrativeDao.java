package ma.sir.ged.dao.facade.core;

import org.springframework.data.jpa.repository.Query;
import ma.sir.ged.zynerator.repository.AbstractRepository;
import ma.sir.ged.bean.core.EntiteAdministrative;
import org.springframework.stereotype.Repository;
import ma.sir.ged.bean.core.EntiteAdministrative;
import java.util.List;


@Repository
public interface EntiteAdministrativeDao extends AbstractRepository<EntiteAdministrative,Long>  {
    EntiteAdministrative findByCode(String code);
    int deleteByCode(String code);

    List<EntiteAdministrative> findByUtilisateurId(Long id);
    int deleteByUtilisateurId(Long id);
    List<EntiteAdministrative> findByEntiteAdministrativeTypeId(Long id);
    int deleteByEntiteAdministrativeTypeId(Long id);

    @Query("SELECT NEW EntiteAdministrative(item.id,item.libelle) FROM EntiteAdministrative item")
    List<EntiteAdministrative> findAllOptimized();
}
