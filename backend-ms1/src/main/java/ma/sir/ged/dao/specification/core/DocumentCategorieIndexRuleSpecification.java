package  ma.sir.ged.dao.specification.core;

import ma.sir.ged.zynerator.specification.AbstractSpecification;
import ma.sir.ged.dao.criteria.core.DocumentCategorieIndexRuleCriteria;
import ma.sir.ged.bean.core.DocumentCategorieIndexRule;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

public class DocumentCategorieIndexRuleSpecification extends  AbstractSpecification<DocumentCategorieIndexRuleCriteria, DocumentCategorieIndexRule>  {

    @Override
    public void constructPredicates() {
        addPredicateId("id", criteria);
        addPredicate("code", criteria.getCode(),criteria.getCodeLike());
        addPredicate("libelle", criteria.getLibelle(),criteria.getLibelleLike());
        addPredicate("expresion", criteria.getExpresion(),criteria.getExpresionLike());
    }

    public DocumentCategorieIndexRuleSpecification(DocumentCategorieIndexRuleCriteria criteria) {
        super(criteria);
    }

    public DocumentCategorieIndexRuleSpecification(DocumentCategorieIndexRuleCriteria criteria, boolean distinct) {
        super(criteria, distinct);
    }

}
