import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentTagDto} from 'app/controller/model/DocumentTag.model';
import {DocumentTagCriteria} from 'app/controller/criteria/DocumentTagCriteria.model';

export class DocumentTagAdminService extends AbstractService<DocumentTagDto, DocumentTagCriteria>{

    constructor() {
        super(ADMIN_URL , 'documentTag/');
    }

};