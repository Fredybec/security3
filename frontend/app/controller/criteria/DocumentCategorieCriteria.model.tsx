import {BaseCriteria} from 'app/zynerator/criteria/BaseCriteria.model';

import {DocumentCategorieIndexCriteria} from './DocumentCategorieIndexCriteria.model';
import {DocumentCategorieModelCriteria} from './DocumentCategorieModelCriteria.model';




export class DocumentCategorieCriteria  extends  BaseCriteria {

    public id: number;

    public code: string;
    public codeLike: string;
    public libelle: string;
    public libelleLike: string;
    public description: string;
    public descriptionLike: string;
      public documentCategorieIndexs: Array<DocumentCategorieIndexCriteria>;
      public documentCategorieModels: Array<DocumentCategorieModelCriteria>;

    constructor() {
        super();
        this.code = '';
        this.codeLike = '';
        this.libelle = '';
        this.libelleLike = '';
        this.description = '';
        this.descriptionLike = '';
    }

}
