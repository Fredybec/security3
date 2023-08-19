package ma.sir.ged.dao.facade.core;

import org.springframework.data.jpa.repository.Query;
import ma.sir.ged.zynerator.repository.AbstractRepository;
import ma.sir.ged.bean.core.Document;
import org.springframework.stereotype.Repository;
import ma.sir.ged.bean.core.Document;
import java.util.List;


@Repository
public interface DocumentDao extends AbstractRepository<Document,Long>  {
    Document findByReference(String reference);
    int deleteByReference(String reference);

    List<Document> findByDocumentTypeId(Long id);
    int deleteByDocumentTypeId(Long id);
    List<Document> findByDocumentStateId(Long id);
    int deleteByDocumentStateId(Long id);
    List<Document> findByDocumentCategorieId(Long id);
    int deleteByDocumentCategorieId(Long id);
    List<Document> findByUtilisateurId(Long id);
    int deleteByUtilisateurId(Long id);
    List<Document> findByEntiteAdministrativeId(Long id);
    int deleteByEntiteAdministrativeId(Long id);
    List<Document> findByDocumentCategorieModelId(Long id);
    int deleteByDocumentCategorieModelId(Long id);

    @Query("SELECT NEW Document(item.id,item.reference) FROM Document item")
    List<Document> findAllOptimized();
}
