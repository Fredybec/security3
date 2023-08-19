import {Button} from 'primereact/button';
import {Column} from 'primereact/column';
import {Dropdown, DropdownChangeEvent} from 'primereact/dropdown';
import {TabView, TabPanel} from 'primereact/tabview';
import {DataTable} from 'primereact/datatable';
import {Dialog} from 'primereact/dialog';
import {InputNumber, InputNumberChangeEvent} from 'primereact/inputnumber';
import {InputText} from 'primereact/inputtext';
import {classNames} from 'primereact/utils';
import { InputTextarea } from 'primereact/inputtextarea';
import React, {useEffect, useState} from 'react';
import {Calendar, CalendarChangeEvent} from 'primereact/calendar';
import { format } from 'date-fns';
import { parse } from 'date-fns';
import { InputSwitch } from 'primereact/inputswitch';
import {MultiSelect, MultiSelectChangeEvent} from 'primereact/multiselect';

import {MessageService} from 'app/zynerator/service/MessageService';
import { FileUpload, FileUploadHandlerEvent } from 'primereact/fileupload';



import {DocumentCollaborateurService} from 'app/controller/service/collaborateur/DocumentCollaborateurService.service';
import  {DocumentDto}  from 'app/controller/model/Document.model';
import {TFunction} from "i18next";
import {Toast} from "primereact/toast";

import {DocumentTypeDto} from 'app/controller/model/DocumentType.model';
import {DocumentTypeCollaborateurService} from 'app/controller/service/collaborateur/DocumentTypeCollaborateurService.service';
import {IndexElementDto} from 'app/controller/model/IndexElement.model';
import {IndexElementCollaborateurService} from 'app/controller/service/collaborateur/IndexElementCollaborateurService.service';
import {EntiteAdministrativeDto} from 'app/controller/model/EntiteAdministrative.model';
import {EntiteAdministrativeCollaborateurService} from 'app/controller/service/collaborateur/EntiteAdministrativeCollaborateurService.service';
import {TagDto} from 'app/controller/model/Tag.model';
import {TagCollaborateurService} from 'app/controller/service/collaborateur/TagCollaborateurService.service';
import {DocumentCategorieDto} from 'app/controller/model/DocumentCategorie.model';
import {DocumentCategorieCollaborateurService} from 'app/controller/service/collaborateur/DocumentCategorieCollaborateurService.service';
import {DocumentTagDto} from 'app/controller/model/DocumentTag.model';
import {DocumentTagCollaborateurService} from 'app/controller/service/collaborateur/DocumentTagCollaborateurService.service';
import {UtilisateurDto} from 'app/controller/model/Utilisateur.model';
import {UtilisateurCollaborateurService} from 'app/controller/service/collaborateur/UtilisateurCollaborateurService.service';
import {DocumentIndexElementDto} from 'app/controller/model/DocumentIndexElement.model';
import {DocumentIndexElementCollaborateurService} from 'app/controller/service/collaborateur/DocumentIndexElementCollaborateurService.service';
import {AccessShareDto} from 'app/controller/model/AccessShare.model';
import {AccessShareCollaborateurService} from 'app/controller/service/collaborateur/AccessShareCollaborateurService.service';
import {DocumentPartageUtilisateurDto} from 'app/controller/model/DocumentPartageUtilisateur.model';
import {DocumentPartageUtilisateurCollaborateurService} from 'app/controller/service/collaborateur/DocumentPartageUtilisateurCollaborateurService.service';
import {DocumentCategorieModelDto} from 'app/controller/model/DocumentCategorieModel.model';
import {DocumentCategorieModelCollaborateurService} from 'app/controller/service/collaborateur/DocumentCategorieModelCollaborateurService.service';
import {DocumentPartageGroupeDto} from 'app/controller/model/DocumentPartageGroupe.model';
import {DocumentPartageGroupeCollaborateurService} from 'app/controller/service/collaborateur/DocumentPartageGroupeCollaborateurService.service';
import {GroupeDto} from 'app/controller/model/Groupe.model';
import {GroupeCollaborateurService} from 'app/controller/service/collaborateur/GroupeCollaborateurService.service';
import {DocumentStateDto} from 'app/controller/model/DocumentState.model';
import {DocumentStateCollaborateurService} from 'app/controller/service/collaborateur/DocumentStateCollaborateurService.service';
import {DocumentCriteria} from "app/controller/criteria/DocumentCriteria.model";
import useEditHook from "app/component/zyhook/useEdit.hook";


type DocumentEditCollaborateurType = {
    visible: boolean,
    onClose: () => void,
    showToast: React.Ref<Toast>,
    selectedItem: DocumentDto
    update: (item: DocumentDto) => void,
    list: DocumentDto[],
    service: DocumentCollaborateurService,
    t: TFunction
}
const Edit: React.FC<DocumentEditCollaborateurType> = ({visible, onClose, showToast, selectedItem, update, list, service, t}) => {


    const isFormValid = () => {
    let errorMessages = new Array<string>();
        if(item.reference == '')
            errorMessages.push("reference is required")
        return errorMessages.length == 0 ;
    }
    const emptyItem = new DocumentDto();


    const {
        item,
        setItem,
        submitted,
        setSubmitted,
        activeIndex,
        setActiveIndex,
        activeTab,
        setActiveTab,
        onInputTextChange,
        onInputDateChange,
        onInputNumerChange,
        onMultiSelectChange,
        onBooleanInputChange,
        onDropdownChange,
        onTabChange,
        hideDialog,
        editItem,
        formateDate,
        parseToIsoFormat,
        adaptDate
        } = useEditHook<DocumentDto, DocumentCriteria>({list, selectedItem, onClose, update, showToast,service, t, isFormValid})

    const [utilisateurs, setUtilisateurs] = useState<UtilisateurDto[]>([]);
    const [entiteAdministratives, setEntiteAdministratives] = useState<EntiteAdministrativeDto[]>([]);
    const [groupes, setGroupes] = useState<GroupeDto[]>([]);
    const [documentTypes, setDocumentTypes] = useState<DocumentTypeDto[]>([]);
    const [documentCategorieModels, setDocumentCategorieModels] = useState<DocumentCategorieModelDto[]>([]);
    const [accessShares, setAccessShares] = useState<AccessShareDto[]>([]);
    const [indexElements, setIndexElements] = useState<IndexElementDto[]>([]);
    const [tags, setTags] = useState<TagDto[]>([]);
    const [documentCategories, setDocumentCategories] = useState<DocumentCategorieDto[]>([]);
    const [documentStates, setDocumentStates] = useState<DocumentStateDto[]>([]);

    const [documentIndexElements, setDocumentIndexElements] = useState<DocumentIndexElementDto>(new DocumentIndexElementDto());
    const [documentPartageGroupes, setDocumentPartageGroupes] = useState<DocumentPartageGroupeDto>(new DocumentPartageGroupeDto());
    const [documentPartageUtilisateurs, setDocumentPartageUtilisateurs] = useState<DocumentPartageUtilisateurDto>(new DocumentPartageUtilisateurDto());
    const [documentTags, setDocumentTags] = useState<DocumentTagDto>(new DocumentTagDto());

    const documentTypeCollaborateurService = new DocumentTypeCollaborateurService();
    const indexElementCollaborateurService = new IndexElementCollaborateurService();
    const entiteAdministrativeCollaborateurService = new EntiteAdministrativeCollaborateurService();
    const tagCollaborateurService = new TagCollaborateurService();
    const documentCategorieCollaborateurService = new DocumentCategorieCollaborateurService();
    const documentTagCollaborateurService = new DocumentTagCollaborateurService();
    const utilisateurCollaborateurService = new UtilisateurCollaborateurService();
    const documentIndexElementCollaborateurService = new DocumentIndexElementCollaborateurService();
    const accessShareCollaborateurService = new AccessShareCollaborateurService();
    const documentPartageUtilisateurCollaborateurService = new DocumentPartageUtilisateurCollaborateurService();
    const documentCategorieModelCollaborateurService = new DocumentCategorieModelCollaborateurService();
    const documentPartageGroupeCollaborateurService = new DocumentPartageGroupeCollaborateurService();
    const groupeCollaborateurService = new GroupeCollaborateurService();
    const documentStateCollaborateurService = new DocumentStateCollaborateurService();
    useEffect(() => {
    documentTypeCollaborateurService.getList().then(({data}) => setDocumentTypes(data)).catch(error => console.log(error));
    documentStateCollaborateurService.getList().then(({data}) => setDocumentStates(data)).catch(error => console.log(error));
    documentCategorieCollaborateurService.getList().then(({data}) => setDocumentCategories(data)).catch(error => console.log(error));
    utilisateurCollaborateurService.getList().then(({data}) => setUtilisateurs(data)).catch(error => console.log(error));
    entiteAdministrativeCollaborateurService.getList().then(({data}) => setEntiteAdministratives(data)).catch(error => console.log(error));
    documentCategorieModelCollaborateurService.getList().then(({data}) => setDocumentCategorieModels(data)).catch(error => console.log(error));


    indexElementCollaborateurService.getList().then(({data}) => setIndexElements(data)).catch(error => console.log(error));

    groupeCollaborateurService.getList().then(({data}) => setGroupes(data)).catch(error => console.log(error));
    accessShareCollaborateurService.getList().then(({data}) => setAccessShares(data)).catch(error => console.log(error));

    utilisateurCollaborateurService.getList().then(({data}) => setUtilisateurs(data)).catch(error => console.log(error));
    accessShareCollaborateurService.getList().then(({data}) => setAccessShares(data)).catch(error => console.log(error));
    tagCollaborateurService.getList().then(({data}) => {
        const DocumentTags = data?.map(prepareDocumentTag)
        setDocumentTags(documentTags)
    })


        }, []);



    const prepareDocumentTag = (tag: TagDto) => {
        const documentTag = new DocumentTagDto();
        documentTag.tag = tag;
        return documentTag;
    }


    const onUpload = (event:any) => {
    service.uploadAndOcr(event);
    }

    const addDocumentIndexElements = () => {
        setSubmitted(true);
        if( item.documentIndexElements == null )
        item.documentIndexElements = new Array<DocumentIndexElementDto>();
        let _item = documentIndexElements;
        if (!_item.id) {
            item.documentIndexElements.push(_item);
            MessageService.showSuccess(showToast, 'DocumentIndexElements Created');
            setItem((prevState :any) => ({...prevState, documentIndexElements: item.documentIndexElements }));
        } else {
            const updatedItems = item.documentIndexElements.map((item) => item.id === documentIndexElements.id ? {...documentIndexElements} : item);
            MessageService.showSuccess(showToast, 'DocumentIndexElements Updated');
            setItem((prevState :any) => ({ ...prevState, documentIndexElements: updatedItems}));
        }
        setDocumentIndexElements(new DocumentIndexElementDto());
    };

    const deleteDocumentIndexElements = (rowData: any) => {
        const updatedItems = item.documentIndexElements.filter((val) => val !== rowData);
        setItem((prevState ) => ({...prevState, documentIndexElements: updatedItems }));
        setDocumentIndexElements(new DocumentIndexElementDto());
        MessageService.showSuccess(showToast, 'DocumentItem Deleted');
    };

    const editDocumentIndexElements = (rowData: any) => {
        setActiveTab(0);
        setDocumentIndexElements(rowData);
    };

    const onInputNumerChangeDocumentIndexElements = (e: any, name: string) => {
        const val = e.value || 0;
        setDocumentIndexElements((prevDocumentIndexElements) => ({ ...prevDocumentIndexElements, [name]: val, }));
    };

    const onDropdownChangeDocumentIndexElements = (e: any, field: string) => {
        setDocumentIndexElements((prevState) => ({ ...prevState, [field]: e.value}));
    };


    const onMultiSelectChangeDocumentIndexElements = (e: any, field: string) => {
        if (e && e.value && Array.isArray(e.value)) {
            const selectedValues = e.value.map(option => option && option.value);
            setDocumentIndexElements(prevState => ({ ...prevState, [field]: selectedValues, }));
        }
    };

    const onBooleanInputChangeDocumentIndexElements = (e: any, name: string) => {
        const val = e.value;
        setDocumentIndexElements((prevItem) => ({ ...prevItem, [name]: val, }));
    };

    const onInputDateChangeDocumentIndexElements = (e: CalendarChangeEvent, name: string) => {
        const val = e.value || '';
        setDocumentIndexElements({ ...documentIndexElements, [name]:val})
    };

    const onInputTextChangeDocumentIndexElements = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>, name: string) => {
        const val = (e.target && e.target.value) || '';
        setDocumentIndexElements({ ...documentIndexElements, [name]:val})
    };
    const addDocumentPartageGroupes = () => {
        setSubmitted(true);
        if( item.documentPartageGroupes == null )
        item.documentPartageGroupes = new Array<DocumentPartageGroupeDto>();
        let _item = documentPartageGroupes;
        if (!_item.id) {
            item.documentPartageGroupes.push(_item);
            MessageService.showSuccess(showToast, 'DocumentPartageGroupes Created');
            setItem((prevState :any) => ({...prevState, documentPartageGroupes: item.documentPartageGroupes }));
        } else {
            const updatedItems = item.documentPartageGroupes.map((item) => item.id === documentPartageGroupes.id ? {...documentPartageGroupes} : item);
            MessageService.showSuccess(showToast, 'DocumentPartageGroupes Updated');
            setItem((prevState :any) => ({ ...prevState, documentPartageGroupes: updatedItems}));
        }
        setDocumentPartageGroupes(new DocumentPartageGroupeDto());
    };

    const deleteDocumentPartageGroupes = (rowData: any) => {
        const updatedItems = item.documentPartageGroupes.filter((val) => val !== rowData);
        setItem((prevState ) => ({...prevState, documentPartageGroupes: updatedItems }));
        setDocumentPartageGroupes(new DocumentPartageGroupeDto());
        MessageService.showSuccess(showToast, 'DocumentItem Deleted');
    };

    const editDocumentPartageGroupes = (rowData: any) => {
        setActiveTab(0);
        setDocumentPartageGroupes(rowData);
    };

    const onInputNumerChangeDocumentPartageGroupes = (e: any, name: string) => {
        const val = e.value || 0;
        setDocumentPartageGroupes((prevDocumentPartageGroupes) => ({ ...prevDocumentPartageGroupes, [name]: val, }));
    };

    const onDropdownChangeDocumentPartageGroupes = (e: any, field: string) => {
        setDocumentPartageGroupes((prevState) => ({ ...prevState, [field]: e.value}));
    };


    const onMultiSelectChangeDocumentPartageGroupes = (e: any, field: string) => {
        if (e && e.value && Array.isArray(e.value)) {
            const selectedValues = e.value.map(option => option && option.value);
            setDocumentPartageGroupes(prevState => ({ ...prevState, [field]: selectedValues, }));
        }
    };

    const onBooleanInputChangeDocumentPartageGroupes = (e: any, name: string) => {
        const val = e.value;
        setDocumentPartageGroupes((prevItem) => ({ ...prevItem, [name]: val, }));
    };

    const onInputDateChangeDocumentPartageGroupes = (e: CalendarChangeEvent, name: string) => {
        const val = e.value || '';
        setDocumentPartageGroupes({ ...documentPartageGroupes, [name]:val})
    };

    const onInputTextChangeDocumentPartageGroupes = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>, name: string) => {
        const val = (e.target && e.target.value) || '';
        setDocumentPartageGroupes({ ...documentPartageGroupes, [name]:val})
    };
    const addDocumentPartageUtilisateurs = () => {
        setSubmitted(true);
        if( item.documentPartageUtilisateurs == null )
        item.documentPartageUtilisateurs = new Array<DocumentPartageUtilisateurDto>();
        let _item = documentPartageUtilisateurs;
        if (!_item.id) {
            item.documentPartageUtilisateurs.push(_item);
            MessageService.showSuccess(showToast, 'DocumentPartageUtilisateurs Created');
            setItem((prevState :any) => ({...prevState, documentPartageUtilisateurs: item.documentPartageUtilisateurs }));
        } else {
            const updatedItems = item.documentPartageUtilisateurs.map((item) => item.id === documentPartageUtilisateurs.id ? {...documentPartageUtilisateurs} : item);
            MessageService.showSuccess(showToast, 'DocumentPartageUtilisateurs Updated');
            setItem((prevState :any) => ({ ...prevState, documentPartageUtilisateurs: updatedItems}));
        }
        setDocumentPartageUtilisateurs(new DocumentPartageUtilisateurDto());
    };

    const deleteDocumentPartageUtilisateurs = (rowData: any) => {
        const updatedItems = item.documentPartageUtilisateurs.filter((val) => val !== rowData);
        setItem((prevState ) => ({...prevState, documentPartageUtilisateurs: updatedItems }));
        setDocumentPartageUtilisateurs(new DocumentPartageUtilisateurDto());
        MessageService.showSuccess(showToast, 'DocumentItem Deleted');
    };

    const editDocumentPartageUtilisateurs = (rowData: any) => {
        setActiveTab(0);
        setDocumentPartageUtilisateurs(rowData);
    };

    const onInputNumerChangeDocumentPartageUtilisateurs = (e: any, name: string) => {
        const val = e.value || 0;
        setDocumentPartageUtilisateurs((prevDocumentPartageUtilisateurs) => ({ ...prevDocumentPartageUtilisateurs, [name]: val, }));
    };

    const onDropdownChangeDocumentPartageUtilisateurs = (e: any, field: string) => {
        setDocumentPartageUtilisateurs((prevState) => ({ ...prevState, [field]: e.value}));
    };


    const onMultiSelectChangeDocumentPartageUtilisateurs = (e: any, field: string) => {
        if (e && e.value && Array.isArray(e.value)) {
            const selectedValues = e.value.map(option => option && option.value);
            setDocumentPartageUtilisateurs(prevState => ({ ...prevState, [field]: selectedValues, }));
        }
    };

    const onBooleanInputChangeDocumentPartageUtilisateurs = (e: any, name: string) => {
        const val = e.value;
        setDocumentPartageUtilisateurs((prevItem) => ({ ...prevItem, [name]: val, }));
    };

    const onInputDateChangeDocumentPartageUtilisateurs = (e: CalendarChangeEvent, name: string) => {
        const val = e.value || '';
        setDocumentPartageUtilisateurs({ ...documentPartageUtilisateurs, [name]:val})
    };

    const onInputTextChangeDocumentPartageUtilisateurs = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>, name: string) => {
        const val = (e.target && e.target.value) || '';
        setDocumentPartageUtilisateurs({ ...documentPartageUtilisateurs, [name]:val})
    };

    const itemDialogFooter = ( <>
        <Button label="Cancel" icon="pi pi-times" text onClick={hideDialog} />
        <Button label="Save" icon="pi pi-check" onClick={editItem} /> </>
    );



    return(
    <Dialog visible={visible} style={{width: '70vw'}} header={t("document.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog}>
        <TabView activeIndex={activeIndex} onTabChange={onTabChange}>
            <TabPanel header={t("document.tabPan")}>
                <div className="formgrid grid">
                    <div className="field col-6">
                        <label htmlFor="reference">{t("document.reference")}</label>
                        <InputText id="reference" value={item ? item.reference : ''} onChange={(e) => onInputTextChange(e, 'reference')} required className={classNames({'p-invalid': submitted && !item.reference})} />
                        {submitted && !item.reference && <small className="p-invalid">Reference is required.</small>}
                    </div>
                        <div className="field col-6">
                            <FileUpload accept=".pdf,.jpg,.png" chooseLabel="Choose File" uploadLabel="Upload" customUpload uploadHandler={onUpload}/>
                        </div>
                    <div className="field col-6">
                        <label htmlFor="uploadDate">{t("document.uploadDate")}</label>
                        <Calendar id="uploadDate" value={adaptDate(item?.uploadDate)} onChange={(e) => onInputDateChange(e, 'uploadDate')} dateFormat="dd/mm/yy" showIcon={true} />
                    </div>
                    <div className="field col-6">
                        <label htmlFor="annee">{t("document.annee")}</label>
                        <InputNumber id="annee" value={item ? item.annee : 0} onChange={(e) => onInputNumerChange(e, 'annee')}/>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="semstre">{t("document.semstre")}</label>
                        <InputNumber id="semstre" value={item ? item.semstre : 0} onChange={(e) => onInputNumerChange(e, 'semstre')}/>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="mois">{t("document.mois")}</label>
                        <InputNumber id="mois" value={item ? item.mois : 0} onChange={(e) => onInputNumerChange(e, 'mois')}/>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="jour">{t("document.jour")}</label>
                        <InputNumber id="jour" value={item ? item.jour : 0} onChange={(e) => onInputNumerChange(e, 'jour')}/>
                    </div>
                    <div className="field col-6">
                        <div  className="label-inputswitch">
                            <label htmlFor="ocr">{t("document.ocr")}</label>
                            <span className="p-float-label">
                                <InputSwitch  id="ocr" checked={item.ocr} onChange={(e) => onBooleanInputChange(e, 'ocr')} />
                            </span>
                        </div>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="content">{t("document.content")}</label>
                        <span className="p-float-label">
                            <InputTextarea id="content" value={item ? item.content : ''} onChange={(e) => onInputTextChange(e, 'content')} rows={5} cols={30}/>
                        </span>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="size">{t("document.size")}</label>
                        <InputNumber id="size" value={item ? item.size : 0} onChange={(e) => onInputNumerChange(e, 'size')}/>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="documentType">{t("document.documentType")}</label>
                        <Dropdown  id="documentTypeDropdown"  value={item ? item.documentType : ''} options={documentTypes} onChange={(e) => onDropdownChange(e, 'documentType')}   placeholder="Sélectionnez un documentType" filter filterPlaceholder="Rechercher un documentType" optionLabel="libelle" showClear />
                    </div>
                    <div className="field col-6">
                        <label htmlFor="documentState">{t("document.documentState")}</label>
                        <Dropdown  id="documentStateDropdown"  value={item ? item.documentState : ''} options={documentStates} onChange={(e) => onDropdownChange(e, 'documentState')}   placeholder="Sélectionnez un documentState" filter filterPlaceholder="Rechercher un documentState" optionLabel="libelle" showClear />
                    </div>
                    <div className="field col-6">
                        <label htmlFor="documentCategorie">{t("document.documentCategorie")}</label>
                        <Dropdown  id="documentCategorieDropdown"  value={item ? item.documentCategorie : ''} options={documentCategories} onChange={(e) => onDropdownChange(e, 'documentCategorie')}   placeholder="Sélectionnez un documentCategorie" filter filterPlaceholder="Rechercher un documentCategorie" optionLabel="libelle" showClear />
                    </div>
                    <div className="field col-6">
                        <label htmlFor="description">{t("document.description")}</label>
                        <span className="p-float-label">
                            <InputTextarea id="description" value={item ? item.description : ''} onChange={(e) => onInputTextChange(e, 'description')} rows={5} cols={30}/>
                        </span>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="utilisateur">{t("document.utilisateur")}</label>
                        <Dropdown  id="utilisateurDropdown"  value={item ? item.utilisateur : ''} options={utilisateurs} onChange={(e) => onDropdownChange(e, 'utilisateur')}   placeholder="Sélectionnez un utilisateur" filter filterPlaceholder="Rechercher un utilisateur" optionLabel="nom" showClear />
                    </div>
                    <div className="field col-6">
                        <div  className="label-inputswitch">
                            <label htmlFor="archive">{t("document.archive")}</label>
                            <span className="p-float-label">
                                <InputSwitch  id="archive" checked={item.archive} onChange={(e) => onBooleanInputChange(e, 'archive')} />
                            </span>
                        </div>
                    </div>
                    <div className="field col-6">
                        <div  className="label-inputswitch">
                            <label htmlFor="versionne">{t("document.versionne")}</label>
                            <span className="p-float-label">
                                <InputSwitch  id="versionne" checked={item.versionne} onChange={(e) => onBooleanInputChange(e, 'versionne')} />
                            </span>
                        </div>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="entiteAdministrative">{t("document.entiteAdministrative")}</label>
                        <Dropdown  id="entiteAdministrativeDropdown"  value={item ? item.entiteAdministrative : ''} options={entiteAdministratives} onChange={(e) => onDropdownChange(e, 'entiteAdministrative')}   placeholder="Sélectionnez un entiteAdministrative" filter filterPlaceholder="Rechercher un entiteAdministrative" optionLabel="libelle" showClear />
                    </div>
                    <div className="field col-6">
                        <label htmlFor="documentCategorieModel">{t("document.documentCategorieModel")}</label>
                        <Dropdown  id="documentCategorieModelDropdown"  value={item ? item.documentCategorieModel : ''} options={documentCategorieModels} onChange={(e) => onDropdownChange(e, 'documentCategorieModel')}   placeholder="Sélectionnez un documentCategorieModel" filter filterPlaceholder="Rechercher un documentCategorieModel" optionLabel="libelle" showClear />
                    </div>
                    <div className="field col-6">
                        <label htmlFor="documentTags">{t("documentTag.tag")}</label>
                        {/*
                        <MultiSelect value={item ? item.documentTags : ''} options={documentTags}  optionLabel="tag.libelle" display="chip" placeholder="Select tag"  maxSelectedLabels={3}  onChange={(e) => onMultiSelectChange(e, 'documentTags')} />
                        */}
                    </div>
                </div>
            </TabPanel>
            <TabPanel header={t("document.documentIndexElements")}>
                        <div className="grid">
                            <div className="field col-6">
                                <label htmlFor="indexElement">{t("documentIndexElement.indexElement")}</label>
                                <Dropdown id="indexElementDropdown" value={documentIndexElements.indexElement} options={indexElements} onChange={(e) => onDropdownChangeDocumentIndexElements(e, 'indexElement')} placeholder="Sélectionnez un indexElement" filter  filterPlaceholder="Rechercher un indexElement"  optionLabel="libelle" showClear />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="value">{t("documentIndexElement.value")}</label>
                                <InputText id="value" value={documentIndexElements.value} onChange={(e) => onInputTextChangeDocumentIndexElements(e, 'value')} required className={classNames({'p-invalid': submitted && !item.documentIndexElements})}/>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="description">{t("documentIndexElement.description")}</label>
                                <span className="p-float-label">
                                    <InputTextarea id="description" value={item ? item.documentIndexElements : ''} onChange={(e) => onInputTextChange(e, 'description')} rows={5} cols={30}/>
                                </span>
                            </div>

                            <div className="field col-1">
                                <Button icon="pi pi-plus" label="OK" className="mt-4" onClick={addDocumentIndexElements} />
                            </div>
                        </div>
                        <div className="p-col">
                        <div className="card">
                            <DataTable value={item.documentIndexElements} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="indexElement.libelle" header={t("documentIndexElement.indexElement")}></Column>
                                <Column field="value" header={t("documentIndexElement.value")} ></Column>
                                <Column field="description" header={t("documentIndexElement.description")} ></Column>
                                <Column header="Actions" body={(rowData) => (
                                    <div>
                                        <Button icon="pi pi-times" rounded severity="warning" className="mr-2 p-button-danger" onClick={()=> deleteDocumentIndexElements(rowData)} />
                                        <Button icon="pi pi-pencil" rounded severity="success" className="mr-2" onClick={()=> editDocumentIndexElements(rowData)} />
                                    </div>
                                )}></Column>
                            </DataTable>
                        </div>
                        </div>
            </TabPanel>
            <TabPanel header={t("document.documentPartageGroupes")}>
                        <div className="grid">
                            <div className="field col-6">
                                <label htmlFor="groupe">{t("documentPartageGroupe.groupe")}</label>
                                <Dropdown id="groupeDropdown" value={documentPartageGroupes.groupe} options={groupes} onChange={(e) => onDropdownChangeDocumentPartageGroupes(e, 'groupe')} placeholder="Sélectionnez un groupe" filter  filterPlaceholder="Rechercher un groupe"  optionLabel="libelle" showClear />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="dateShare">{t("documentPartageGroupe.dateShare")}</label>
                                <Calendar id="dateShare" value={adaptDate(documentPartageGroupes?.dateShare)}  onChange={(e) => onInputDateChangeDocumentPartageGroupes(e, 'dateShare')} dateFormat="dd/mm/yy" showIcon={true}  />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="accessShare">{t("documentPartageGroupe.accessShare")}</label>
                                <Dropdown id="accessShareDropdown" value={documentPartageGroupes.accessShare} options={accessShares} onChange={(e) => onDropdownChangeDocumentPartageGroupes(e, 'accessShare')} placeholder="Sélectionnez un accessShare" filter  filterPlaceholder="Rechercher un accessShare"  optionLabel="libelle" showClear />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="description">{t("documentPartageGroupe.description")}</label>
                                <span className="p-float-label">
                                    <InputTextarea id="description" value={item ? item.documentPartageGroupes : ''} onChange={(e) => onInputTextChange(e, 'description')} rows={5} cols={30}/>
                                </span>
                            </div>

                            <div className="field col-1">
                                <Button icon="pi pi-plus" label="OK" className="mt-4" onClick={addDocumentPartageGroupes} />
                            </div>
                        </div>
                        <div className="p-col">
                        <div className="card">
                            <DataTable value={item.documentPartageGroupes} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="groupe.libelle" header={t("documentPartageGroupe.groupe")}></Column>
                                <Column field="dateShare" header={t("documentPartageGroupe.dateShare")} body={formateDate("dateShare")}></Column>
                                <Column field="accessShare.libelle" header={t("documentPartageGroupe.accessShare")}></Column>
                                <Column field="description" header={t("documentPartageGroupe.description")} ></Column>
                                <Column header="Actions" body={(rowData) => (
                                    <div>
                                        <Button icon="pi pi-times" rounded severity="warning" className="mr-2 p-button-danger" onClick={()=> deleteDocumentPartageGroupes(rowData)} />
                                        <Button icon="pi pi-pencil" rounded severity="success" className="mr-2" onClick={()=> editDocumentPartageGroupes(rowData)} />
                                    </div>
                                )}></Column>
                            </DataTable>
                        </div>
                        </div>
            </TabPanel>
            <TabPanel header={t("document.documentPartageUtilisateurs")}>
                        <div className="grid">
                            <div className="field col-6">
                                <label htmlFor="utilisateur">{t("documentPartageUtilisateur.utilisateur")}</label>
                                <Dropdown id="utilisateurDropdown" value={documentPartageUtilisateurs.utilisateur} options={utilisateurs} onChange={(e) => onDropdownChangeDocumentPartageUtilisateurs(e, 'utilisateur')} placeholder="Sélectionnez un utilisateur" filter  filterPlaceholder="Rechercher un utilisateur"  optionLabel="nom" showClear />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="dateShare">{t("documentPartageUtilisateur.dateShare")}</label>
                                <Calendar id="dateShare" value={adaptDate(documentPartageUtilisateurs?.dateShare)}  onChange={(e) => onInputDateChangeDocumentPartageUtilisateurs(e, 'dateShare')} dateFormat="dd/mm/yy" showIcon={true}  />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="accessShare">{t("documentPartageUtilisateur.accessShare")}</label>
                                <Dropdown id="accessShareDropdown" value={documentPartageUtilisateurs.accessShare} options={accessShares} onChange={(e) => onDropdownChangeDocumentPartageUtilisateurs(e, 'accessShare')} placeholder="Sélectionnez un accessShare" filter  filterPlaceholder="Rechercher un accessShare"  optionLabel="libelle" showClear />
                            </div>
                            <div className="field col-6">
                                <label htmlFor="description">{t("documentPartageUtilisateur.description")}</label>
                                <span className="p-float-label">
                                    <InputTextarea id="description" value={item ? item.documentPartageUtilisateurs : ''} onChange={(e) => onInputTextChange(e, 'description')} rows={5} cols={30}/>
                                </span>
                            </div>

                            <div className="field col-1">
                                <Button icon="pi pi-plus" label="OK" className="mt-4" onClick={addDocumentPartageUtilisateurs} />
                            </div>
                        </div>
                        <div className="p-col">
                        <div className="card">
                            <DataTable value={item.documentPartageUtilisateurs} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="utilisateur.nom" header={t("documentPartageUtilisateur.utilisateur")}></Column>
                                <Column field="dateShare" header={t("documentPartageUtilisateur.dateShare")} body={formateDate("dateShare")}></Column>
                                <Column field="accessShare.libelle" header={t("documentPartageUtilisateur.accessShare")}></Column>
                                <Column field="description" header={t("documentPartageUtilisateur.description")} ></Column>
                                <Column header="Actions" body={(rowData) => (
                                    <div>
                                        <Button icon="pi pi-times" rounded severity="warning" className="mr-2 p-button-danger" onClick={()=> deleteDocumentPartageUtilisateurs(rowData)} />
                                        <Button icon="pi pi-pencil" rounded severity="success" className="mr-2" onClick={()=> editDocumentPartageUtilisateurs(rowData)} />
                                    </div>
                                )}></Column>
                            </DataTable>
                        </div>
                        </div>
            </TabPanel>
        </TabView>
    </Dialog>
);
};
export default Edit;


