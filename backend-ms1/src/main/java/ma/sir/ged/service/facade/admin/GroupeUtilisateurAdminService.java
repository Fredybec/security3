package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.GroupeUtilisateur;
import ma.sir.ged.dao.criteria.core.GroupeUtilisateurCriteria;
import ma.sir.ged.dao.criteria.history.GroupeUtilisateurHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface GroupeUtilisateurAdminService extends  IService<GroupeUtilisateur,GroupeUtilisateurCriteria, GroupeUtilisateurHistoryCriteria>  {

    List<GroupeUtilisateur> findByGroupeId(Long id);
    int deleteByGroupeId(Long id);
    List<GroupeUtilisateur> findByUtilisateurId(Long id);
    int deleteByUtilisateurId(Long id);
    List<GroupeUtilisateur> findByEtatUtilisateurId(Long id);
    int deleteByEtatUtilisateurId(Long id);
    List<GroupeUtilisateur> findByRoleUtilisateurId(Long id);
    int deleteByRoleUtilisateurId(Long id);



}
