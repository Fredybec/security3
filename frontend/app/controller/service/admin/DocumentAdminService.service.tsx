import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentDto} from 'app/controller/model/Document.model';
import {DocumentCriteria} from 'app/controller/criteria/DocumentCriteria.model';
import axios, {AxiosResponse} from "axios";

export class DocumentAdminService extends AbstractService<DocumentDto, DocumentCriteria>{

    constructor() {
        super(ADMIN_URL , 'document/');
    }
};
