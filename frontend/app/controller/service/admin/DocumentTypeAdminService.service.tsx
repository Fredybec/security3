import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentTypeDto} from 'app/controller/model/DocumentType.model';
import {DocumentTypeCriteria} from 'app/controller/criteria/DocumentTypeCriteria.model';

export class DocumentTypeAdminService extends AbstractService<DocumentTypeDto, DocumentTypeCriteria>{

    constructor() {
        super(ADMIN_URL , 'documentType/');
    }

};