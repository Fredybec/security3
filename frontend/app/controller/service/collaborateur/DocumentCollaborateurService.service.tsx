import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentDto} from 'app/controller/model/Document.model';
import {DocumentCriteria} from 'app/controller/criteria/DocumentCriteria.model';

export class DocumentCollaborateurService extends AbstractService<DocumentDto, DocumentCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'document/');
    }

};