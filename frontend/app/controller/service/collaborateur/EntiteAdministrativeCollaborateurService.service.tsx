import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {EntiteAdministrativeDto} from 'app/controller/model/EntiteAdministrative.model';
import {EntiteAdministrativeCriteria} from 'app/controller/criteria/EntiteAdministrativeCriteria.model';

export class EntiteAdministrativeCollaborateurService extends AbstractService<EntiteAdministrativeDto, EntiteAdministrativeCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'entiteAdministrative/');
    }

};