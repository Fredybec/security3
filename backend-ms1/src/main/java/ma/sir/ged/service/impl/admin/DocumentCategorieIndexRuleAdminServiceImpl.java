package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.DocumentCategorieIndexRule;
import ma.sir.ged.bean.history.DocumentCategorieIndexRuleHistory;
import ma.sir.ged.dao.criteria.core.DocumentCategorieIndexRuleCriteria;
import ma.sir.ged.dao.criteria.history.DocumentCategorieIndexRuleHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentCategorieIndexRuleDao;
import ma.sir.ged.dao.facade.history.DocumentCategorieIndexRuleHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentCategorieIndexRuleSpecification;
import ma.sir.ged.service.facade.admin.DocumentCategorieIndexRuleAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;







import java.util.List;
@Service
public class DocumentCategorieIndexRuleAdminServiceImpl extends AbstractServiceImpl<DocumentCategorieIndexRule,DocumentCategorieIndexRuleHistory, DocumentCategorieIndexRuleCriteria, DocumentCategorieIndexRuleHistoryCriteria, DocumentCategorieIndexRuleDao,
DocumentCategorieIndexRuleHistoryDao> implements DocumentCategorieIndexRuleAdminService {



    public DocumentCategorieIndexRule findByReferenceEntity(DocumentCategorieIndexRule t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(DocumentCategorieIndexRule.class,DocumentCategorieIndexRuleHistory.class, DocumentCategorieIndexRuleHistoryCriteria.class, DocumentCategorieIndexRuleSpecification.class);
    }


    public DocumentCategorieIndexRuleAdminServiceImpl(DocumentCategorieIndexRuleDao dao, DocumentCategorieIndexRuleHistoryDao historyDao) {
        super(dao, historyDao);
    }

}