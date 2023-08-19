import { ADMIN_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {UtilisateurDto} from 'app/controller/model/Utilisateur.model';
import {UtilisateurCriteria} from 'app/controller/criteria/UtilisateurCriteria.model';

export class UtilisateurAdminService extends AbstractService<UtilisateurDto, UtilisateurCriteria>{

    constructor() {
        super(ADMIN_URL , 'utilisateur/');
    }

};