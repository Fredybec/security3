import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {AccessShareDto} from 'app/controller/model/AccessShare.model';
import {AccessShareCriteria} from 'app/controller/criteria/AccessShareCriteria.model';

export class AccessShareAdminService extends AbstractService<AccessShareDto, AccessShareCriteria>{

    constructor() {
        super(ADMIN_URL , 'accessShare/');
    }

};