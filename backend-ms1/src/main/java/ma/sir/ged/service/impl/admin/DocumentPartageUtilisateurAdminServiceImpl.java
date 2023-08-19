package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.DocumentPartageUtilisateur;
import ma.sir.ged.bean.history.DocumentPartageUtilisateurHistory;
import ma.sir.ged.dao.criteria.core.DocumentPartageUtilisateurCriteria;
import ma.sir.ged.dao.criteria.history.DocumentPartageUtilisateurHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentPartageUtilisateurDao;
import ma.sir.ged.dao.facade.history.DocumentPartageUtilisateurHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentPartageUtilisateurSpecification;
import ma.sir.ged.service.facade.admin.DocumentPartageUtilisateurAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;


import ma.sir.ged.service.facade.admin.UtilisateurAdminService ;
import ma.sir.ged.service.facade.admin.AccessShareAdminService ;
import ma.sir.ged.service.facade.admin.DocumentAdminService ;



import java.util.List;
@Service
public class DocumentPartageUtilisateurAdminServiceImpl extends AbstractServiceImpl<DocumentPartageUtilisateur,DocumentPartageUtilisateurHistory, DocumentPartageUtilisateurCriteria, DocumentPartageUtilisateurHistoryCriteria, DocumentPartageUtilisateurDao,
DocumentPartageUtilisateurHistoryDao> implements DocumentPartageUtilisateurAdminService {




    public List<DocumentPartageUtilisateur> findByDocumentId(Long id){
        return dao.findByDocumentId(id);
    }
    public int deleteByDocumentId(Long id){
        return dao.deleteByDocumentId(id);
    }
    public List<DocumentPartageUtilisateur> findByUtilisateurId(Long id){
        return dao.findByUtilisateurId(id);
    }
    public int deleteByUtilisateurId(Long id){
        return dao.deleteByUtilisateurId(id);
    }
    public List<DocumentPartageUtilisateur> findByAccessShareId(Long id){
        return dao.findByAccessShareId(id);
    }
    public int deleteByAccessShareId(Long id){
        return dao.deleteByAccessShareId(id);
    }




    public void configure() {
        super.configure(DocumentPartageUtilisateur.class,DocumentPartageUtilisateurHistory.class, DocumentPartageUtilisateurHistoryCriteria.class, DocumentPartageUtilisateurSpecification.class);
    }

    @Autowired
    private UtilisateurAdminService utilisateurService ;
    @Autowired
    private AccessShareAdminService accessShareService ;
    @Autowired
    private DocumentAdminService documentService ;

    public DocumentPartageUtilisateurAdminServiceImpl(DocumentPartageUtilisateurDao dao, DocumentPartageUtilisateurHistoryDao historyDao) {
        super(dao, historyDao);
    }

}