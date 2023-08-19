package  ma.sir.ged.dao.specification.core;

import ma.sir.ged.zynerator.specification.AbstractSpecification;
import ma.sir.ged.dao.criteria.core.AccessShareCriteria;
import ma.sir.ged.bean.core.AccessShare;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

public class AccessShareSpecification extends  AbstractSpecification<AccessShareCriteria, AccessShare>  {

    @Override
    public void constructPredicates() {
        addPredicateId("id", criteria);
        addPredicate("code", criteria.getCode(),criteria.getCodeLike());
        addPredicate("libelle", criteria.getLibelle(),criteria.getLibelleLike());
    }

    public AccessShareSpecification(AccessShareCriteria criteria) {
        super(criteria);
    }

    public AccessShareSpecification(AccessShareCriteria criteria, boolean distinct) {
        super(criteria, distinct);
    }

}
