import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {EntiteAdministrativeDto} from 'app/controller/model/EntiteAdministrative.model';
import {EntiteAdministrativeCriteria} from 'app/controller/criteria/EntiteAdministrativeCriteria.model';

export class EntiteAdministrativeAdminService extends AbstractService<EntiteAdministrativeDto, EntiteAdministrativeCriteria>{

    constructor() {
        super(ADMIN_URL , 'entiteAdministrative/');
    }

};