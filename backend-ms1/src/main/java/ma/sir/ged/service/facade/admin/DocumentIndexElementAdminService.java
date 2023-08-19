package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.DocumentIndexElement;
import ma.sir.ged.dao.criteria.core.DocumentIndexElementCriteria;
import ma.sir.ged.dao.criteria.history.DocumentIndexElementHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface DocumentIndexElementAdminService extends  IService<DocumentIndexElement,DocumentIndexElementCriteria, DocumentIndexElementHistoryCriteria>  {

    List<DocumentIndexElement> findByIndexElementId(Long id);
    int deleteByIndexElementId(Long id);
    List<DocumentIndexElement> findByDocumentId(Long id);
    int deleteByDocumentId(Long id);



}
