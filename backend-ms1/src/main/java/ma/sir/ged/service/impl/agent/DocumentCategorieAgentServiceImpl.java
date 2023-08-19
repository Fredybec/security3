package ma.sir.ged.service.impl.agent;

import ma.sir.ged.bean.core.DocumentCategorie;
import ma.sir.ged.bean.history.DocumentCategorieHistory;
import ma.sir.ged.dao.criteria.core.DocumentCategorieCriteria;
import ma.sir.ged.dao.criteria.history.DocumentCategorieHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentCategorieDao;
import ma.sir.ged.dao.facade.history.DocumentCategorieHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentCategorieSpecification;
import ma.sir.ged.service.facade.agent.DocumentCategorieAgentService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import ma.sir.ged.bean.core.DocumentCategorieIndex;
import ma.sir.ged.bean.core.DocumentCategorieModel;

import ma.sir.ged.service.facade.agent.DocumentCategorieModelAgentService ;
import ma.sir.ged.service.facade.agent.DocumentCategorieIndexAgentService ;



import java.util.List;
@Service
public class DocumentCategorieAgentServiceImpl extends AbstractServiceImpl<DocumentCategorie,DocumentCategorieHistory, DocumentCategorieCriteria, DocumentCategorieHistoryCriteria, DocumentCategorieDao,
DocumentCategorieHistoryDao> implements DocumentCategorieAgentService {


    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class, readOnly = false)
    public DocumentCategorie create(DocumentCategorie t) {
        super.create(t);
        if (t.getDocumentCategorieIndexs() != null) {
                t.getDocumentCategorieIndexs().forEach(element-> {
                    element.setDocumentCategorie(t);
                    documentCategorieIndexService.create(element);
            });
        }
        if (t.getDocumentCategorieModels() != null) {
                t.getDocumentCategorieModels().forEach(element-> {
                    element.setDocumentCategorie(t);
                    documentCategorieModelService.create(element);
            });
        }
        return t;
    }

    public DocumentCategorie findWithAssociatedLists(Long id){
        DocumentCategorie result = dao.findById(id).orElse(null);
        if(result!=null && result.getId() != null) {
            result.setDocumentCategorieIndexs(documentCategorieIndexService.findByDocumentCategorieId(id));
            result.setDocumentCategorieModels(documentCategorieModelService.findByDocumentCategorieId(id));
        }
        return result;
    }
    @Transactional
    public void deleteAssociatedLists(Long id) {
        documentCategorieIndexService.deleteByDocumentCategorieId(id);
        documentCategorieModelService.deleteByDocumentCategorieId(id);
    }


    public void updateWithAssociatedLists(DocumentCategorie documentCategorie){
    if(documentCategorie !=null && documentCategorie.getId() != null){
            List<List<DocumentCategorieIndex>> resultDocumentCategorieIndexs= documentCategorieIndexService.getToBeSavedAndToBeDeleted(documentCategorieIndexService.findByDocumentCategorieId(documentCategorie.getId()),documentCategorie.getDocumentCategorieIndexs());
            documentCategorieIndexService.delete(resultDocumentCategorieIndexs.get(1));
            ListUtil.emptyIfNull(resultDocumentCategorieIndexs.get(0)).forEach(e -> e.setDocumentCategorie(documentCategorie));
            documentCategorieIndexService.update(resultDocumentCategorieIndexs.get(0),true);
            List<List<DocumentCategorieModel>> resultDocumentCategorieModels= documentCategorieModelService.getToBeSavedAndToBeDeleted(documentCategorieModelService.findByDocumentCategorieId(documentCategorie.getId()),documentCategorie.getDocumentCategorieModels());
            documentCategorieModelService.delete(resultDocumentCategorieModels.get(1));
            ListUtil.emptyIfNull(resultDocumentCategorieModels.get(0)).forEach(e -> e.setDocumentCategorie(documentCategorie));
            documentCategorieModelService.update(resultDocumentCategorieModels.get(0),true);
    }
    }

    public DocumentCategorie findByReferenceEntity(DocumentCategorie t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(DocumentCategorie.class,DocumentCategorieHistory.class, DocumentCategorieHistoryCriteria.class, DocumentCategorieSpecification.class);
    }

    @Autowired
    private DocumentCategorieModelAgentService documentCategorieModelService ;
    @Autowired
    private DocumentCategorieIndexAgentService documentCategorieIndexService ;

    public DocumentCategorieAgentServiceImpl(DocumentCategorieDao dao, DocumentCategorieHistoryDao historyDao) {
        super(dao, historyDao);
    }

}