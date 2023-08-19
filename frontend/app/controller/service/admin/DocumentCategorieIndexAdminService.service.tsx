import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentCategorieIndexDto} from 'app/controller/model/DocumentCategorieIndex.model';
import {DocumentCategorieIndexCriteria} from 'app/controller/criteria/DocumentCategorieIndexCriteria.model';

export class DocumentCategorieIndexAdminService extends AbstractService<DocumentCategorieIndexDto, DocumentCategorieIndexCriteria>{

    constructor() {
        super(ADMIN_URL , 'documentCategorieIndex/');
    }

};