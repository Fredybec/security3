import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {UtilisateurDto} from 'app/controller/model/Utilisateur.model';
import {UtilisateurCriteria} from 'app/controller/criteria/UtilisateurCriteria.model';

export class UtilisateurCollaborateurService extends AbstractService<UtilisateurDto, UtilisateurCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'utilisateur/');
    }

};