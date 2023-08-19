import {BaseCriteria} from 'app/zynerator/criteria/BaseCriteria.model';

import {AccessShareCriteria} from './AccessShareCriteria.model';
import {DocumentCriteria} from './DocumentCriteria.model';
import {UtilisateurCriteria} from './UtilisateurCriteria.model';




export class DocumentPartageUtilisateurCriteria  extends  BaseCriteria {

    public id: number;

    public dateShare: Date;
    public dateShareFrom: Date;
    public dateShareTo: Date;
    public description: string;
    public descriptionLike: string;
  public document: DocumentCriteria ;
  public documents: Array<DocumentCriteria> ;
  public utilisateur: UtilisateurCriteria ;
  public utilisateurs: Array<UtilisateurCriteria> ;
  public accessShare: AccessShareCriteria ;
  public accessShares: Array<AccessShareCriteria> ;

    constructor() {
        super();
        this.dateShare = null;
        this.dateShareFrom  = null;
        this.dateShareTo = null;
        this.description = '';
        this.descriptionLike = '';
        this.document ;
        this.documents = new Array<DocumentCriteria>() ;
        this.utilisateur ;
        this.utilisateurs = new Array<UtilisateurCriteria>() ;
        this.accessShare ;
        this.accessShares = new Array<AccessShareCriteria>() ;
    }

}
