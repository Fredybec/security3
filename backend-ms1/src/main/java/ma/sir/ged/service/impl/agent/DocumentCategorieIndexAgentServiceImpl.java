package ma.sir.ged.service.impl.agent;

import ma.sir.ged.bean.core.DocumentCategorieIndex;
import ma.sir.ged.bean.history.DocumentCategorieIndexHistory;
import ma.sir.ged.dao.criteria.core.DocumentCategorieIndexCriteria;
import ma.sir.ged.dao.criteria.history.DocumentCategorieIndexHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentCategorieIndexDao;
import ma.sir.ged.dao.facade.history.DocumentCategorieIndexHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentCategorieIndexSpecification;
import ma.sir.ged.service.facade.agent.DocumentCategorieIndexAgentService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;


import org.springframework.beans.factory.annotation.Autowired;


import ma.sir.ged.service.facade.agent.IndexElementAgentService ;
import ma.sir.ged.service.facade.agent.DocumentCategorieAgentService ;
import ma.sir.ged.service.facade.agent.DocumentCategorieIndexRuleAgentService ;



import java.util.List;
@Service
public class DocumentCategorieIndexAgentServiceImpl extends AbstractServiceImpl<DocumentCategorieIndex,DocumentCategorieIndexHistory, DocumentCategorieIndexCriteria, DocumentCategorieIndexHistoryCriteria, DocumentCategorieIndexDao,
DocumentCategorieIndexHistoryDao> implements DocumentCategorieIndexAgentService {




    public List<DocumentCategorieIndex> findByIndexElementId(Long id){
        return dao.findByIndexElementId(id);
    }
    public int deleteByIndexElementId(Long id){
        return dao.deleteByIndexElementId(id);
    }
    public List<DocumentCategorieIndex> findByDocumentCategorieId(Long id){
        return dao.findByDocumentCategorieId(id);
    }
    public int deleteByDocumentCategorieId(Long id){
        return dao.deleteByDocumentCategorieId(id);
    }
    public List<DocumentCategorieIndex> findByDocumentCategorieIndexRuleId(Long id){
        return dao.findByDocumentCategorieIndexRuleId(id);
    }
    public int deleteByDocumentCategorieIndexRuleId(Long id){
        return dao.deleteByDocumentCategorieIndexRuleId(id);
    }




    public void configure() {
        super.configure(DocumentCategorieIndex.class,DocumentCategorieIndexHistory.class, DocumentCategorieIndexHistoryCriteria.class, DocumentCategorieIndexSpecification.class);
    }

    @Autowired
    private IndexElementAgentService indexElementService ;
    @Autowired
    private DocumentCategorieAgentService documentCategorieService ;
    @Autowired
    private DocumentCategorieIndexRuleAgentService documentCategorieIndexRuleService ;

    public DocumentCategorieIndexAgentServiceImpl(DocumentCategorieIndexDao dao, DocumentCategorieIndexHistoryDao historyDao) {
        super(dao, historyDao);
    }

}