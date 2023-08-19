package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.Utilisateur;
import ma.sir.ged.dao.criteria.core.UtilisateurCriteria;
import ma.sir.ged.dao.criteria.history.UtilisateurHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface UtilisateurAdminService extends  IService<Utilisateur,UtilisateurCriteria, UtilisateurHistoryCriteria>  {

    List<Utilisateur> findByGenderId(Long id);
    int deleteByGenderId(Long id);



}
