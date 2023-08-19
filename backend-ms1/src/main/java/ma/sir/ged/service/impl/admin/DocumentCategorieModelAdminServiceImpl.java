package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.DocumentCategorieModel;
import ma.sir.ged.bean.history.DocumentCategorieModelHistory;
import ma.sir.ged.dao.criteria.core.DocumentCategorieModelCriteria;
import ma.sir.ged.dao.criteria.history.DocumentCategorieModelHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentCategorieModelDao;
import ma.sir.ged.dao.facade.history.DocumentCategorieModelHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentCategorieModelSpecification;
import ma.sir.ged.service.facade.admin.DocumentCategorieModelAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;


import ma.sir.ged.service.facade.admin.DocumentCategorieAdminService ;



import java.util.List;
@Service
public class DocumentCategorieModelAdminServiceImpl extends AbstractServiceImpl<DocumentCategorieModel,DocumentCategorieModelHistory, DocumentCategorieModelCriteria, DocumentCategorieModelHistoryCriteria, DocumentCategorieModelDao,
DocumentCategorieModelHistoryDao> implements DocumentCategorieModelAdminService {



    public DocumentCategorieModel findByReferenceEntity(DocumentCategorieModel t){
        return  dao.findByCode(t.getCode());
    }

    public List<DocumentCategorieModel> findByDocumentCategorieId(Long id){
        return dao.findByDocumentCategorieId(id);
    }
    public int deleteByDocumentCategorieId(Long id){
        return dao.deleteByDocumentCategorieId(id);
    }




    public void configure() {
        super.configure(DocumentCategorieModel.class,DocumentCategorieModelHistory.class, DocumentCategorieModelHistoryCriteria.class, DocumentCategorieModelSpecification.class);
    }

    @Autowired
    private DocumentCategorieAdminService documentCategorieService ;

    public DocumentCategorieModelAdminServiceImpl(DocumentCategorieModelDao dao, DocumentCategorieModelHistoryDao historyDao) {
        super(dao, historyDao);
    }

}