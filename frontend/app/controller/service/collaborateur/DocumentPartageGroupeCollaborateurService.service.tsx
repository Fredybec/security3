import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentPartageGroupeDto} from 'app/controller/model/DocumentPartageGroupe.model';
import {DocumentPartageGroupeCriteria} from 'app/controller/criteria/DocumentPartageGroupeCriteria.model';

export class DocumentPartageGroupeCollaborateurService extends AbstractService<DocumentPartageGroupeDto, DocumentPartageGroupeCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'documentPartageGroupe/');
    }

};