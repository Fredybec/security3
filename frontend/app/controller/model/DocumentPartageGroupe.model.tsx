import {BaseDto} from 'app/zynerator/dto/BaseDto.model';

import {GroupeDto} from 'app/controller/model/Groupe.model';
import {AccessShareDto} from 'app/controller/model/AccessShare.model';
import {DocumentDto} from 'app/controller/model/Document.model';

export class DocumentPartageGroupeDto extends BaseDto{

   public dateShare: Date;

    public description: string;

    public document: DocumentDto ;
    public groupe: GroupeDto ;
    public accessShare: AccessShareDto ;


    constructor() {
        super();
        this.dateShare = null;
        this.description = '';
        this.document;
        this.groupe;
        this.accessShare;
        }

    getClassName() {
        return "Document partage groupe";
    }
}
