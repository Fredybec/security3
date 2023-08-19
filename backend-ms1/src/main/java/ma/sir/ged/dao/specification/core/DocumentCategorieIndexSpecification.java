package  ma.sir.ged.dao.specification.core;

import ma.sir.ged.zynerator.specification.AbstractSpecification;
import ma.sir.ged.dao.criteria.core.DocumentCategorieIndexCriteria;
import ma.sir.ged.bean.core.DocumentCategorieIndex;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

public class DocumentCategorieIndexSpecification extends  AbstractSpecification<DocumentCategorieIndexCriteria, DocumentCategorieIndex>  {

    @Override
    public void constructPredicates() {
        addPredicateId("id", criteria);
        addPredicateFk("indexElement","id", criteria.getIndexElement()==null?null:criteria.getIndexElement().getId());
        addPredicateFk("indexElement","id", criteria.getIndexElements());
        addPredicateFk("indexElement","code", criteria.getIndexElement()==null?null:criteria.getIndexElement().getCode());
        addPredicateFk("documentCategorie","id", criteria.getDocumentCategorie()==null?null:criteria.getDocumentCategorie().getId());
        addPredicateFk("documentCategorie","id", criteria.getDocumentCategories());
        addPredicateFk("documentCategorie","code", criteria.getDocumentCategorie()==null?null:criteria.getDocumentCategorie().getCode());
        addPredicateFk("documentCategorieIndexRule","id", criteria.getDocumentCategorieIndexRule()==null?null:criteria.getDocumentCategorieIndexRule().getId());
        addPredicateFk("documentCategorieIndexRule","id", criteria.getDocumentCategorieIndexRules());
        addPredicateFk("documentCategorieIndexRule","code", criteria.getDocumentCategorieIndexRule()==null?null:criteria.getDocumentCategorieIndexRule().getCode());
    }

    public DocumentCategorieIndexSpecification(DocumentCategorieIndexCriteria criteria) {
        super(criteria);
    }

    public DocumentCategorieIndexSpecification(DocumentCategorieIndexCriteria criteria, boolean distinct) {
        super(criteria, distinct);
    }

}
