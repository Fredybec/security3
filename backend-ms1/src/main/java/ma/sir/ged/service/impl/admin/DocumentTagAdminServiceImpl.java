package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.DocumentTag;
import ma.sir.ged.bean.history.DocumentTagHistory;
import ma.sir.ged.dao.criteria.core.DocumentTagCriteria;
import ma.sir.ged.dao.criteria.history.DocumentTagHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentTagDao;
import ma.sir.ged.dao.facade.history.DocumentTagHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentTagSpecification;
import ma.sir.ged.service.facade.admin.DocumentTagAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;


import ma.sir.ged.service.facade.admin.TagAdminService ;
import ma.sir.ged.service.facade.admin.DocumentAdminService ;



import java.util.List;
@Service
public class DocumentTagAdminServiceImpl extends AbstractServiceImpl<DocumentTag,DocumentTagHistory, DocumentTagCriteria, DocumentTagHistoryCriteria, DocumentTagDao,
DocumentTagHistoryDao> implements DocumentTagAdminService {




    public List<DocumentTag> findByDocumentId(Long id){
        return dao.findByDocumentId(id);
    }
    public int deleteByDocumentId(Long id){
        return dao.deleteByDocumentId(id);
    }
    public List<DocumentTag> findByTagId(Long id){
        return dao.findByTagId(id);
    }
    public int deleteByTagId(Long id){
        return dao.deleteByTagId(id);
    }




    public void configure() {
        super.configure(DocumentTag.class,DocumentTagHistory.class, DocumentTagHistoryCriteria.class, DocumentTagSpecification.class);
    }

    @Autowired
    private TagAdminService tagService ;
    @Autowired
    private DocumentAdminService documentService ;

    public DocumentTagAdminServiceImpl(DocumentTagDao dao, DocumentTagHistoryDao historyDao) {
        super(dao, historyDao);
    }

}