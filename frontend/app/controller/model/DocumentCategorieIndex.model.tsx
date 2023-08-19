import {BaseDto} from 'app/zynerator/dto/BaseDto.model';

import {DocumentCategorieDto} from 'app/controller/model/DocumentCategorie.model';
import {DocumentCategorieIndexRuleDto} from 'app/controller/model/DocumentCategorieIndexRule.model';
import {IndexElementDto} from 'app/controller/model/IndexElement.model';

export class DocumentCategorieIndexDto extends BaseDto{

    public indexElement: IndexElementDto ;
    public documentCategorie: DocumentCategorieDto ;
    public documentCategorieIndexRule: DocumentCategorieIndexRuleDto ;


    constructor() {
        super();
        this.indexElement;
        this.documentCategorie;
        this.documentCategorieIndexRule;
        }

    getClassName() {
        return "Document categorie index";
    }
}
