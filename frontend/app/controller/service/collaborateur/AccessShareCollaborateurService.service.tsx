import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {AccessShareDto} from 'app/controller/model/AccessShare.model';
import {AccessShareCriteria} from 'app/controller/criteria/AccessShareCriteria.model';

export class AccessShareCollaborateurService extends AbstractService<AccessShareDto, AccessShareCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'accessShare/');
    }

};