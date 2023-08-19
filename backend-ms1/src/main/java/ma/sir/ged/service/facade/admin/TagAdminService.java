package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.Tag;
import ma.sir.ged.dao.criteria.core.TagCriteria;
import ma.sir.ged.dao.criteria.history.TagHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface TagAdminService extends  IService<Tag,TagCriteria, TagHistoryCriteria>  {




}
