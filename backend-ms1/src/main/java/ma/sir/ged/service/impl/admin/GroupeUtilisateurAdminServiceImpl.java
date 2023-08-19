package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.GroupeUtilisateur;
import ma.sir.ged.bean.history.GroupeUtilisateurHistory;
import ma.sir.ged.dao.criteria.core.GroupeUtilisateurCriteria;
import ma.sir.ged.dao.criteria.history.GroupeUtilisateurHistoryCriteria;
import ma.sir.ged.dao.facade.core.GroupeUtilisateurDao;
import ma.sir.ged.dao.facade.history.GroupeUtilisateurHistoryDao;
import ma.sir.ged.dao.specification.core.GroupeUtilisateurSpecification;
import ma.sir.ged.service.facade.admin.GroupeUtilisateurAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;


import ma.sir.ged.service.facade.admin.GroupeAdminService ;
import ma.sir.ged.service.facade.admin.UtilisateurAdminService ;
import ma.sir.ged.service.facade.admin.RoleUtilisateurAdminService ;
import ma.sir.ged.service.facade.admin.EtatUtilisateurAdminService ;



import java.util.List;
@Service
public class GroupeUtilisateurAdminServiceImpl extends AbstractServiceImpl<GroupeUtilisateur,GroupeUtilisateurHistory, GroupeUtilisateurCriteria, GroupeUtilisateurHistoryCriteria, GroupeUtilisateurDao,
GroupeUtilisateurHistoryDao> implements GroupeUtilisateurAdminService {




    public List<GroupeUtilisateur> findByGroupeId(Long id){
        return dao.findByGroupeId(id);
    }
    public int deleteByGroupeId(Long id){
        return dao.deleteByGroupeId(id);
    }
    public List<GroupeUtilisateur> findByUtilisateurId(Long id){
        return dao.findByUtilisateurId(id);
    }
    public int deleteByUtilisateurId(Long id){
        return dao.deleteByUtilisateurId(id);
    }
    public List<GroupeUtilisateur> findByEtatUtilisateurId(Long id){
        return dao.findByEtatUtilisateurId(id);
    }
    public int deleteByEtatUtilisateurId(Long id){
        return dao.deleteByEtatUtilisateurId(id);
    }
    public List<GroupeUtilisateur> findByRoleUtilisateurId(Long id){
        return dao.findByRoleUtilisateurId(id);
    }
    public int deleteByRoleUtilisateurId(Long id){
        return dao.deleteByRoleUtilisateurId(id);
    }




    public void configure() {
        super.configure(GroupeUtilisateur.class,GroupeUtilisateurHistory.class, GroupeUtilisateurHistoryCriteria.class, GroupeUtilisateurSpecification.class);
    }

    @Autowired
    private GroupeAdminService groupeService ;
    @Autowired
    private UtilisateurAdminService utilisateurService ;
    @Autowired
    private RoleUtilisateurAdminService roleUtilisateurService ;
    @Autowired
    private EtatUtilisateurAdminService etatUtilisateurService ;

    public GroupeUtilisateurAdminServiceImpl(GroupeUtilisateurDao dao, GroupeUtilisateurHistoryDao historyDao) {
        super(dao, historyDao);
    }

}