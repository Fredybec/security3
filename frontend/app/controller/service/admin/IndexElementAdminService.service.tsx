import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {IndexElementDto} from 'app/controller/model/IndexElement.model';
import {IndexElementCriteria} from 'app/controller/criteria/IndexElementCriteria.model';

export class IndexElementAdminService extends AbstractService<IndexElementDto, IndexElementCriteria>{

    constructor() {
        super(ADMIN_URL , 'indexElement/');
    }

};