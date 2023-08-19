import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {GenderDto} from 'app/controller/model/Gender.model';
import {GenderCriteria} from 'app/controller/criteria/GenderCriteria.model';

export class GenderCollaborateurService extends AbstractService<GenderDto, GenderCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'gender/');
    }

};