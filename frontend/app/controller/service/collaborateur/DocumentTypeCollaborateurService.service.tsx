import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentTypeDto} from 'app/controller/model/DocumentType.model';
import {DocumentTypeCriteria} from 'app/controller/criteria/DocumentTypeCriteria.model';

export class DocumentTypeCollaborateurService extends AbstractService<DocumentTypeDto, DocumentTypeCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'documentType/');
    }

};