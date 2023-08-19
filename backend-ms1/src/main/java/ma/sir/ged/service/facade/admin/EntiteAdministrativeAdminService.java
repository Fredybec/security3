package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.EntiteAdministrative;
import ma.sir.ged.dao.criteria.core.EntiteAdministrativeCriteria;
import ma.sir.ged.dao.criteria.history.EntiteAdministrativeHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface EntiteAdministrativeAdminService extends  IService<EntiteAdministrative,EntiteAdministrativeCriteria, EntiteAdministrativeHistoryCriteria>  {

    List<EntiteAdministrative> findByUtilisateurId(Long id);
    int deleteByUtilisateurId(Long id);
    List<EntiteAdministrative> findByEntiteAdministrativeTypeId(Long id);
    int deleteByEntiteAdministrativeTypeId(Long id);



}
