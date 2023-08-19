package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.IndexElement;
import ma.sir.ged.bean.history.IndexElementHistory;
import ma.sir.ged.dao.criteria.core.IndexElementCriteria;
import ma.sir.ged.dao.criteria.history.IndexElementHistoryCriteria;
import ma.sir.ged.dao.facade.core.IndexElementDao;
import ma.sir.ged.dao.facade.history.IndexElementHistoryDao;
import ma.sir.ged.dao.specification.core.IndexElementSpecification;
import ma.sir.ged.service.facade.admin.IndexElementAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;







import java.util.List;
@Service
public class IndexElementAdminServiceImpl extends AbstractServiceImpl<IndexElement,IndexElementHistory, IndexElementCriteria, IndexElementHistoryCriteria, IndexElementDao,
IndexElementHistoryDao> implements IndexElementAdminService {



    public IndexElement findByReferenceEntity(IndexElement t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(IndexElement.class,IndexElementHistory.class, IndexElementHistoryCriteria.class, IndexElementSpecification.class);
    }


    public IndexElementAdminServiceImpl(IndexElementDao dao, IndexElementHistoryDao historyDao) {
        super(dao, historyDao);
    }

}