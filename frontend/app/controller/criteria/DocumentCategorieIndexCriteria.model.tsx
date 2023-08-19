import {BaseCriteria} from 'app/zynerator/criteria/BaseCriteria.model';

import {DocumentCategorieCriteria} from './DocumentCategorieCriteria.model';
import {DocumentCategorieIndexRuleCriteria} from './DocumentCategorieIndexRuleCriteria.model';
import {IndexElementCriteria} from './IndexElementCriteria.model';




export class DocumentCategorieIndexCriteria  extends  BaseCriteria {

    public id: number;

  public indexElement: IndexElementCriteria ;
  public indexElements: Array<IndexElementCriteria> ;
  public documentCategorie: DocumentCategorieCriteria ;
  public documentCategories: Array<DocumentCategorieCriteria> ;
  public documentCategorieIndexRule: DocumentCategorieIndexRuleCriteria ;
  public documentCategorieIndexRules: Array<DocumentCategorieIndexRuleCriteria> ;

    constructor() {
        super();
        this.indexElement ;
        this.indexElements = new Array<IndexElementCriteria>() ;
        this.documentCategorie ;
        this.documentCategories = new Array<DocumentCategorieCriteria>() ;
        this.documentCategorieIndexRule ;
        this.documentCategorieIndexRules = new Array<DocumentCategorieIndexRuleCriteria>() ;
    }

}
