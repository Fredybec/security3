import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {RoleUtilisateurDto} from 'app/controller/model/RoleUtilisateur.model';
import {RoleUtilisateurCriteria} from 'app/controller/criteria/RoleUtilisateurCriteria.model';

export class RoleUtilisateurAdminService extends AbstractService<RoleUtilisateurDto, RoleUtilisateurCriteria>{

    constructor() {
        super(ADMIN_URL , 'roleUtilisateur/');
    }

};