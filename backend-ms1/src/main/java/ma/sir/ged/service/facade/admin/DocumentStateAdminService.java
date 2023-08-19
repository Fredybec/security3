package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.DocumentState;
import ma.sir.ged.dao.criteria.core.DocumentStateCriteria;
import ma.sir.ged.dao.criteria.history.DocumentStateHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface DocumentStateAdminService extends  IService<DocumentState,DocumentStateCriteria, DocumentStateHistoryCriteria>  {




}
