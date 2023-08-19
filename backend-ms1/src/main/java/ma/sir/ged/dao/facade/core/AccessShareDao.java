package ma.sir.ged.dao.facade.core;

import org.springframework.data.jpa.repository.Query;
import ma.sir.ged.zynerator.repository.AbstractRepository;
import ma.sir.ged.bean.core.AccessShare;
import org.springframework.stereotype.Repository;
import ma.sir.ged.bean.core.AccessShare;
import java.util.List;


@Repository
public interface AccessShareDao extends AbstractRepository<AccessShare,Long>  {
    AccessShare findByCode(String code);
    int deleteByCode(String code);


    @Query("SELECT NEW AccessShare(item.id,item.libelle) FROM AccessShare item")
    List<AccessShare> findAllOptimized();
}
