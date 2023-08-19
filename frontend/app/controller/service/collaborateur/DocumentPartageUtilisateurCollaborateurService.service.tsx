import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentPartageUtilisateurDto} from 'app/controller/model/DocumentPartageUtilisateur.model';
import {DocumentPartageUtilisateurCriteria} from 'app/controller/criteria/DocumentPartageUtilisateurCriteria.model';

export class DocumentPartageUtilisateurCollaborateurService extends AbstractService<DocumentPartageUtilisateurDto, DocumentPartageUtilisateurCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'documentPartageUtilisateur/');
    }

};