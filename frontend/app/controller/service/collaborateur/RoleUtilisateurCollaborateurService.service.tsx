import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {RoleUtilisateurDto} from 'app/controller/model/RoleUtilisateur.model';
import {RoleUtilisateurCriteria} from 'app/controller/criteria/RoleUtilisateurCriteria.model';

export class RoleUtilisateurCollaborateurService extends AbstractService<RoleUtilisateurDto, RoleUtilisateurCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'roleUtilisateur/');
    }

};