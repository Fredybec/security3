import { COLLABORATEUR_URL } from 'layout/AppConfig';
import AbstractService from "app/zynerator/service/AbstractService";

import {TagDto} from 'app/controller/model/Tag.model';
import {TagCriteria} from 'app/controller/criteria/TagCriteria.model';

export class TagCollaborateurService extends AbstractService<TagDto, TagCriteria>{

    constructor() {
        super(COLLABORATEUR_URL , 'tag/');
    }

};