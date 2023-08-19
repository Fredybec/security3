import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentStateDto} from 'app/controller/model/DocumentState.model';
import {DocumentStateCriteria} from 'app/controller/criteria/DocumentStateCriteria.model';

export class DocumentStateCollaborateurService extends AbstractService<DocumentStateDto, DocumentStateCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'documentState/');
    }

};