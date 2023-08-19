import {BaseCriteria} from 'app/zynerator/criteria/BaseCriteria.model';

import {GroupeCriteria} from './GroupeCriteria.model';
import {AccessShareCriteria} from './AccessShareCriteria.model';
import {DocumentCriteria} from './DocumentCriteria.model';




export class DocumentPartageGroupeCriteria  extends  BaseCriteria {

    public id: number;

    public dateShare: Date;
    public dateShareFrom: Date;
    public dateShareTo: Date;
    public description: string;
    public descriptionLike: string;
  public document: DocumentCriteria ;
  public documents: Array<DocumentCriteria> ;
  public groupe: GroupeCriteria ;
  public groupes: Array<GroupeCriteria> ;
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
        this.groupe ;
        this.groupes = new Array<GroupeCriteria>() ;
        this.accessShare ;
        this.accessShares = new Array<AccessShareCriteria>() ;
    }

}
