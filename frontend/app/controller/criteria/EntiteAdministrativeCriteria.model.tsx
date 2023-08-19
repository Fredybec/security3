import {BaseCriteria} from 'app/zynerator/criteria/BaseCriteria.model';

import {EntiteAdministrativeTypeCriteria} from './EntiteAdministrativeTypeCriteria.model';
import {UtilisateurCriteria} from './UtilisateurCriteria.model';




export class EntiteAdministrativeCriteria  extends  BaseCriteria {

    public id: number;

    public code: string;
    public codeLike: string;
    public referenceGed: string;
    public referenceGedLike: string;
    public description: string;
    public descriptionLike: string;
    public libelle: string;
    public libelleLike: string;
  public entiteAdministrativeParent: EntiteAdministrativeCriteria ;
  public entiteAdministrativeParents: Array<EntiteAdministrativeCriteria> ;
  public chef: UtilisateurCriteria ;
  public chefs: Array<UtilisateurCriteria> ;
  public entiteAdministrativeType: EntiteAdministrativeTypeCriteria ;
  public entiteAdministrativeTypes: Array<EntiteAdministrativeTypeCriteria> ;
      public utilisateurs: Array<UtilisateurCriteria>;

    constructor() {
        super();
        this.code = '';
        this.codeLike = '';
        this.referenceGed = '';
        this.referenceGedLike = '';
        this.description = '';
        this.descriptionLike = '';
        this.libelle = '';
        this.libelleLike = '';
        this.entiteAdministrativeParent ;
        this.entiteAdministrativeParents = new Array<EntiteAdministrativeCriteria>() ;
        this.chef ;
        this.chefs = new Array<UtilisateurCriteria>() ;
        this.entiteAdministrativeType ;
        this.entiteAdministrativeTypes = new Array<EntiteAdministrativeTypeCriteria>() ;
    }

}
