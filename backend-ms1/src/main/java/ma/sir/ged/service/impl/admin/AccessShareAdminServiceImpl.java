package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.AccessShare;
import ma.sir.ged.bean.history.AccessShareHistory;
import ma.sir.ged.dao.criteria.core.AccessShareCriteria;
import ma.sir.ged.dao.criteria.history.AccessShareHistoryCriteria;
import ma.sir.ged.dao.facade.core.AccessShareDao;
import ma.sir.ged.dao.facade.history.AccessShareHistoryDao;
import ma.sir.ged.dao.specification.core.AccessShareSpecification;
import ma.sir.ged.service.facade.admin.AccessShareAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;







import java.util.List;
@Service
public class AccessShareAdminServiceImpl extends AbstractServiceImpl<AccessShare,AccessShareHistory, AccessShareCriteria, AccessShareHistoryCriteria, AccessShareDao,
AccessShareHistoryDao> implements AccessShareAdminService {



    public AccessShare findByReferenceEntity(AccessShare t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(AccessShare.class,AccessShareHistory.class, AccessShareHistoryCriteria.class, AccessShareSpecification.class);
    }


    public AccessShareAdminServiceImpl(AccessShareDao dao, AccessShareHistoryDao historyDao) {
        super(dao, historyDao);
    }

}