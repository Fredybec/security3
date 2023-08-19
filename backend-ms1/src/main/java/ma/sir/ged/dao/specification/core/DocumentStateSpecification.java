package  ma.sir.ged.dao.specification.core;

import ma.sir.ged.zynerator.specification.AbstractSpecification;
import ma.sir.ged.dao.criteria.core.DocumentStateCriteria;
import ma.sir.ged.bean.core.DocumentState;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

public class DocumentStateSpecification extends  AbstractSpecification<DocumentStateCriteria, DocumentState>  {

    @Override
    public void constructPredicates() {
        addPredicateId("id", criteria);
        addPredicate("code", criteria.getCode(),criteria.getCodeLike());
        addPredicate("libelle", criteria.getLibelle(),criteria.getLibelleLike());
        addPredicate("style", criteria.getStyle(),criteria.getStyleLike());
    }

    public DocumentStateSpecification(DocumentStateCriteria criteria) {
        super(criteria);
    }

    public DocumentStateSpecification(DocumentStateCriteria criteria, boolean distinct) {
        super(criteria, distinct);
    }

}
