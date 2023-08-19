import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {DocumentTagDto} from 'app/controller/model/DocumentTag.model';
import {DocumentTagCriteria} from 'app/controller/criteria/DocumentTagCriteria.model';

export class DocumentTagCollaborateurService extends AbstractService<DocumentTagDto, DocumentTagCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'documentTag/');
    }

};