package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.RoleUtilisateur;
import ma.sir.ged.bean.history.RoleUtilisateurHistory;
import ma.sir.ged.dao.criteria.core.RoleUtilisateurCriteria;
import ma.sir.ged.dao.criteria.history.RoleUtilisateurHistoryCriteria;
import ma.sir.ged.dao.facade.core.RoleUtilisateurDao;
import ma.sir.ged.dao.facade.history.RoleUtilisateurHistoryDao;
import ma.sir.ged.dao.specification.core.RoleUtilisateurSpecification;
import ma.sir.ged.service.facade.admin.RoleUtilisateurAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;







import java.util.List;
@Service
public class RoleUtilisateurAdminServiceImpl extends AbstractServiceImpl<RoleUtilisateur,RoleUtilisateurHistory, RoleUtilisateurCriteria, RoleUtilisateurHistoryCriteria, RoleUtilisateurDao,
RoleUtilisateurHistoryDao> implements RoleUtilisateurAdminService {



    public RoleUtilisateur findByReferenceEntity(RoleUtilisateur t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(RoleUtilisateur.class,RoleUtilisateurHistory.class, RoleUtilisateurHistoryCriteria.class, RoleUtilisateurSpecification.class);
    }


    public RoleUtilisateurAdminServiceImpl(RoleUtilisateurDao dao, RoleUtilisateurHistoryDao historyDao) {
        super(dao, historyDao);
    }

}