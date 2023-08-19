import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {EtatUtilisateurDto} from 'app/controller/model/EtatUtilisateur.model';
import {EtatUtilisateurCriteria} from 'app/controller/criteria/EtatUtilisateurCriteria.model';

export class EtatUtilisateurCollaborateurService extends AbstractService<EtatUtilisateurDto, EtatUtilisateurCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'etatUtilisateur/');
    }

};