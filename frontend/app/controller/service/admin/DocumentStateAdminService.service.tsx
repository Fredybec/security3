import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentStateDto} from 'app/controller/model/DocumentState.model';
import {DocumentStateCriteria} from 'app/controller/criteria/DocumentStateCriteria.model';

export class DocumentStateAdminService extends AbstractService<DocumentStateDto, DocumentStateCriteria>{

    constructor() {
        super(ADMIN_URL , 'documentState/');
    }

};