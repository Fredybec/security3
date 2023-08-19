import {BaseDto} from 'app/zynerator/dto/BaseDto.model';

import {DocumentStateDto} from 'app/controller/model/DocumentState.model';
import {DocumentPartageGroupeDto} from 'app/controller/model/DocumentPartageGroupe.model';
import {DocumentTagDto} from 'app/controller/model/DocumentTag.model';
import {DocumentCategorieDto} from 'app/controller/model/DocumentCategorie.model';
import {DocumentIndexElementDto} from 'app/controller/model/DocumentIndexElement.model';
import {DocumentPartageUtilisateurDto} from 'app/controller/model/DocumentPartageUtilisateur.model';
import {DocumentCategorieModelDto} from 'app/controller/model/DocumentCategorieModel.model';
import {DocumentTypeDto} from 'app/controller/model/DocumentType.model';
import {EntiteAdministrativeDto} from 'app/controller/model/EntiteAdministrative.model';
import {UtilisateurDto} from 'app/controller/model/Utilisateur.model';

export class DocumentDto extends BaseDto{

    public reference: string;


   public uploadDate: Date;

    public annee: null | number;

    public semstre: null | number;

    public mois: null | number;

    public jour: null | number;

   public ocr: boolean;

    public content: string;

    public size: null | number;

    public description: string;

   public archive: boolean;

   public versionne: boolean;

    public documentType: DocumentTypeDto ;
    public documentState: DocumentStateDto ;
    public documentCategorie: DocumentCategorieDto ;
    public utilisateur: UtilisateurDto ;
    public entiteAdministrative: EntiteAdministrativeDto ;
    public documentCategorieModel: DocumentCategorieModelDto ;
     public documentIndexElements: Array<DocumentIndexElementDto>;
     public documentPartageGroupes: Array<DocumentPartageGroupeDto>;
     public documentPartageUtilisateurs: Array<DocumentPartageUtilisateurDto>;
     public documentTags: Array<DocumentTagDto>;


    constructor() {
        super();
        this.reference = '';
        this.uploadDate = null;
        this.annee = null;
        this.semstre = null;
        this.mois = null;
        this.jour = null;
        this.ocr = null;
        this.content = '';
        this.size = null;
        this.description = '';
        this.archive = null;
        this.versionne = null;
        this.documentType;
        this.documentState;
        this.documentCategorie;
        this.utilisateur;
        this.entiteAdministrative;
        this.documentCategorieModel;
        this.documentIndexElements = new Array<DocumentIndexElementDto>();
        this.documentPartageGroupes = new Array<DocumentPartageGroupeDto>();
        this.documentPartageUtilisateurs = new Array<DocumentPartageUtilisateurDto>();
        this.documentTags = new Array<DocumentTagDto>();
        }

    getClassName() {
        return "Document";
    }
}
