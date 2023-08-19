package ma.sir.ged.zynerator.specification;


import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import ma.sir.ged.zynerator.audit.AuditBusinessObjectEnhanced;
import ma.sir.ged.zynerator.criteria.BaseCriteriaEnhanced;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractSpecificationEnhanced<Criteria extends BaseCriteriaEnhanced, T extends AuditBusinessObjectEnhanced> extends AbstractSpecification<Criteria, T>  {


    public AbstractSpecificationEnhanced(Criteria criteria) {
        super(criteria);
    }

    public AbstractSpecificationEnhanced(Criteria criteria, boolean distinct) {
        super(criteria,distinct);
    }


    @Override
    public Predicate toPredicate(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder builder) {
        List<Predicate> predicates = new ArrayList<>();
        attachSearchElement(root, query, builder, predicates);
        if (criteria != null) {
            addEnhacedPredicate();
            constructPredicates();
            addOrderAndFilter();
        }
    return getResult();
    }

    private void addEnhacedPredicate() {
        addPredicateBool("actif",criteria.isActifLike());
        addPredicate("ordre",criteria.getOrdre(), criteria.getOrdreLike());
    }



}
