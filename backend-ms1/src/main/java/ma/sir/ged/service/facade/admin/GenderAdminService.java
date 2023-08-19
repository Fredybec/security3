package ma.sir.ged.service.facade.admin;

import java.util.List;
import ma.sir.ged.bean.core.Gender;
import ma.sir.ged.dao.criteria.core.GenderCriteria;
import ma.sir.ged.dao.criteria.history.GenderHistoryCriteria;
import ma.sir.ged.zynerator.service.IService;


public interface GenderAdminService extends  IService<Gender,GenderCriteria, GenderHistoryCriteria>  {




}
