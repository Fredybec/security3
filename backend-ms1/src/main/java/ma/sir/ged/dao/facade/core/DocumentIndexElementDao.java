package ma.sir.ged.dao.facade.core;

import ma.sir.ged.zynerator.repository.AbstractRepository;
import ma.sir.ged.bean.core.DocumentIndexElement;
import org.springframework.stereotype.Repository;
import java.util.List;


@Repository
public interface DocumentIndexElementDao extends AbstractRepository<DocumentIndexElement,Long>  {

    List<DocumentIndexElement> findByIndexElementId(Long id);
    int deleteByIndexElementId(Long id);
    List<DocumentIndexElement> findByDocumentId(Long id);
    int deleteByDocumentId(Long id);

}
