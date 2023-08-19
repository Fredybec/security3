package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.Groupe;
import ma.sir.ged.bean.history.GroupeHistory;
import ma.sir.ged.dao.criteria.core.GroupeCriteria;
import ma.sir.ged.dao.criteria.history.GroupeHistoryCriteria;
import ma.sir.ged.dao.facade.core.GroupeDao;
import ma.sir.ged.dao.facade.history.GroupeHistoryDao;
import ma.sir.ged.dao.specification.core.GroupeSpecification;
import ma.sir.ged.service.facade.admin.GroupeAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import ma.sir.ged.bean.core.GroupeUtilisateur;

import ma.sir.ged.service.facade.admin.UtilisateurAdminService ;
import ma.sir.ged.service.facade.admin.GroupeUtilisateurAdminService ;



import java.util.List;
@Service
public class GroupeAdminServiceImpl extends AbstractServiceImpl<Groupe,GroupeHistory, GroupeCriteria, GroupeHistoryCriteria, GroupeDao,
GroupeHistoryDao> implements GroupeAdminService {


    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class, readOnly = false)
    public Groupe create(Groupe t) {
        super.create(t);
        if (t.getGroupeUtilisateurs() != null) {
                t.getGroupeUtilisateurs().forEach(element-> {
                    element.setGroupe(t);
                    groupeUtilisateurService.create(element);
            });
        }
        return t;
    }

    public Groupe findWithAssociatedLists(Long id){
        Groupe result = dao.findById(id).orElse(null);
        if(result!=null && result.getId() != null) {
            result.setGroupeUtilisateurs(groupeUtilisateurService.findByGroupeId(id));
        }
        return result;
    }
    @Transactional
    public void deleteAssociatedLists(Long id) {
        groupeUtilisateurService.deleteByGroupeId(id);
    }


    public void updateWithAssociatedLists(Groupe groupe){
    if(groupe !=null && groupe.getId() != null){
            List<List<GroupeUtilisateur>> resultGroupeUtilisateurs= groupeUtilisateurService.getToBeSavedAndToBeDeleted(groupeUtilisateurService.findByGroupeId(groupe.getId()),groupe.getGroupeUtilisateurs());
            groupeUtilisateurService.delete(resultGroupeUtilisateurs.get(1));
            ListUtil.emptyIfNull(resultGroupeUtilisateurs.get(0)).forEach(e -> e.setGroupe(groupe));
            groupeUtilisateurService.update(resultGroupeUtilisateurs.get(0),true);
    }
    }

    public Groupe findByReferenceEntity(Groupe t){
        return  dao.findByCode(t.getCode());
    }

    public List<Groupe> findByUtilisateurId(Long id){
        return dao.findByUtilisateurId(id);
    }
    public int deleteByUtilisateurId(Long id){
        return dao.deleteByUtilisateurId(id);
    }




    public void configure() {
        super.configure(Groupe.class,GroupeHistory.class, GroupeHistoryCriteria.class, GroupeSpecification.class);
    }

    @Autowired
    private UtilisateurAdminService utilisateurService ;
    @Autowired
    private GroupeUtilisateurAdminService groupeUtilisateurService ;

    public GroupeAdminServiceImpl(GroupeDao dao, GroupeHistoryDao historyDao) {
        super(dao, historyDao);
    }

}