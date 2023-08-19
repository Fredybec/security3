package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.DocumentPartageGroupe;
import ma.sir.ged.bean.history.DocumentPartageGroupeHistory;
import ma.sir.ged.dao.criteria.core.DocumentPartageGroupeCriteria;
import ma.sir.ged.dao.criteria.history.DocumentPartageGroupeHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentPartageGroupeDao;
import ma.sir.ged.dao.facade.history.DocumentPartageGroupeHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentPartageGroupeSpecification;
import ma.sir.ged.service.facade.admin.DocumentPartageGroupeAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;


import ma.sir.ged.service.facade.admin.GroupeAdminService ;
import ma.sir.ged.service.facade.admin.AccessShareAdminService ;
import ma.sir.ged.service.facade.admin.DocumentAdminService ;



import java.util.List;
@Service
public class DocumentPartageGroupeAdminServiceImpl extends AbstractServiceImpl<DocumentPartageGroupe,DocumentPartageGroupeHistory, DocumentPartageGroupeCriteria, DocumentPartageGroupeHistoryCriteria, DocumentPartageGroupeDao,
DocumentPartageGroupeHistoryDao> implements DocumentPartageGroupeAdminService {




    public List<DocumentPartageGroupe> findByDocumentId(Long id){
        return dao.findByDocumentId(id);
    }
    public int deleteByDocumentId(Long id){
        return dao.deleteByDocumentId(id);
    }
    public List<DocumentPartageGroupe> findByGroupeId(Long id){
        return dao.findByGroupeId(id);
    }
    public int deleteByGroupeId(Long id){
        return dao.deleteByGroupeId(id);
    }
    public List<DocumentPartageGroupe> findByAccessShareId(Long id){
        return dao.findByAccessShareId(id);
    }
    public int deleteByAccessShareId(Long id){
        return dao.deleteByAccessShareId(id);
    }




    public void configure() {
        super.configure(DocumentPartageGroupe.class,DocumentPartageGroupeHistory.class, DocumentPartageGroupeHistoryCriteria.class, DocumentPartageGroupeSpecification.class);
    }

    @Autowired
    private GroupeAdminService groupeService ;
    @Autowired
    private AccessShareAdminService accessShareService ;
    @Autowired
    private DocumentAdminService documentService ;

    public DocumentPartageGroupeAdminServiceImpl(DocumentPartageGroupeDao dao, DocumentPartageGroupeHistoryDao historyDao) {
        super(dao, historyDao);
    }

}