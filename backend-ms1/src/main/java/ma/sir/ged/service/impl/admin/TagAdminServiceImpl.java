package ma.sir.ged.service.impl.admin;

import ma.sir.ged.bean.core.Tag;
import ma.sir.ged.bean.history.TagHistory;
import ma.sir.ged.dao.criteria.core.TagCriteria;
import ma.sir.ged.dao.criteria.history.TagHistoryCriteria;
import ma.sir.ged.dao.facade.core.TagDao;
import ma.sir.ged.dao.facade.history.TagHistoryDao;
import ma.sir.ged.dao.specification.core.TagSpecification;
import ma.sir.ged.service.facade.admin.TagAdminService;
import ma.sir.ged.zynerator.service.AbstractServiceImpl;
import ma.sir.ged.zynerator.util.ListUtil;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;







import java.util.List;
@Service
public class TagAdminServiceImpl extends AbstractServiceImpl<Tag,TagHistory, TagCriteria, TagHistoryCriteria, TagDao,
TagHistoryDao> implements TagAdminService {



    public Tag findByReferenceEntity(Tag t){
        return  dao.findByCode(t.getCode());
    }





    public void configure() {
        super.configure(Tag.class,TagHistory.class, TagHistoryCriteria.class, TagSpecification.class);
    }


    public TagAdminServiceImpl(TagDao dao, TagHistoryDao historyDao) {
        super(dao, historyDao);
    }

}