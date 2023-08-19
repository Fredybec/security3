import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentIndexElementDto} from 'app/controller/model/DocumentIndexElement.model';
import {DocumentIndexElementCriteria} from 'app/controller/criteria/DocumentIndexElementCriteria.model';

export class DocumentIndexElementAdminService extends AbstractService<DocumentIndexElementDto, DocumentIndexElementCriteria>{

    constructor() {
        super(ADMIN_URL , 'documentIndexElement/');
    }

};