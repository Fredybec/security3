package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.DocumentState;
import ma.sir.ged.bean.history.DocumentStateHistory;
import ma.sir.ged.dao.criteria.core.DocumentStateCriteria;
import ma.sir.ged.dao.criteria.history.DocumentStateHistoryCriteria;
import ma.sir.ged.dao.facade.core.DocumentStateDao;
import ma.sir.ged.dao.facade.history.DocumentStateHistoryDao;
import ma.sir.ged.dao.specification.core.DocumentStateSpecification;
import ma.sir.ged.service.facade.admin.DocumentStateAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;







import java.util.List;
@Service
public class DocumentStateAdminServiceImpl extends AbstractServiceImpl<DocumentState,DocumentStateHistory, DocumentStateCriteria, DocumentStateHistoryCriteria, DocumentStateDao,
DocumentStateHistoryDao> implements DocumentStateAdminService {



    public DocumentState findByReferenceEntity(DocumentState t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(DocumentState.class,DocumentStateHistory.class, DocumentStateHistoryCriteria.class, DocumentStateSpecification.class);
    }


    public DocumentStateAdminServiceImpl(DocumentStateDao dao, DocumentStateHistoryDao historyDao) {
        super(dao, historyDao);
    }

}