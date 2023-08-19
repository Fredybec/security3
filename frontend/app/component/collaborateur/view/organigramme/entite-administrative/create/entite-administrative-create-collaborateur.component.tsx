import {Button} from 'primereact/button';
import {Column} from 'primereact/column';
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
import {InputSwitch, InputSwitchChangeEvent} from 'primereact/inputswitch';
import {Dropdown, DropdownChangeEvent} from 'primereact/dropdown';
import {MultiSelect, MultiSelectChangeEvent} from 'primereact/multiselect';
import {MessageService} from 'app/zynerator/service/MessageService';

import {EntiteAdministrativeCollaborateurService} from 'app/controller/service/collaborateur/EntiteAdministrativeCollaborateurService.service';
import  {EntiteAdministrativeDto}  from 'app/controller/model/EntiteAdministrative.model';
import {EntiteAdministrativeCriteria} from "app/controller/criteria/EntiteAdministrativeCriteria.model";

import {GenderDto} from 'app/controller/model/Gender.model';
import {GenderCollaborateurService} from 'app/controller/service/collaborateur/GenderCollaborateurService.service';
import {UtilisateurDto} from 'app/controller/model/Utilisateur.model';
import {UtilisateurCollaborateurService} from 'app/controller/service/collaborateur/UtilisateurCollaborateurService.service';
import {EntiteAdministrativeTypeDto} from 'app/controller/model/EntiteAdministrativeType.model';
import {EntiteAdministrativeTypeCollaborateurService} from 'app/controller/service/collaborateur/EntiteAdministrativeTypeCollaborateurService.service';
import {TFunction} from "i18next";
import {Toast} from "primereact/toast";
import useCreateHook from "app/component/zyhook/useCreate.hook";



type EntiteAdministrativeCreateCollaborateurType = {
    visible: boolean,
    onClose: () => void,
    add: (item: EntiteAdministrativeDto) => void,
    showToast: React.Ref<Toast>,
    list: EntiteAdministrativeDto[],
    service: EntiteAdministrativeCollaborateurService,
    t: TFunction
}
const Create: React.FC<EntiteAdministrativeCreateCollaborateurType> = ({visible, onClose, add, showToast, list, service, t}) => {


    const isFormValid = () => {
    let errorMessages = new Array<string>();
                if(item.code == '')
                errorMessages.push("code is required")
                if(item.libelle == '')
                errorMessages.push("libelle is required")
        return errorMessages.length == 0 ;
    }
    const emptyItem = new EntiteAdministrativeDto();
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
            onTabChange,
            onDropdownChange,
            hideDialog,
            saveItem,
            formateDate
        } = useCreateHook<EntiteAdministrativeDto, EntiteAdministrativeCriteria>({list, emptyItem, onClose, add, showToast,service, isFormValid})
    const [entiteAdministrativeTypes, setEntiteAdministrativeTypes] = useState<EntiteAdministrativeTypeDto[]>([]);
    const [genders, setGenders] = useState<GenderDto[]>([]);
    const [entiteAdministrativeParents, setEntiteAdministrativeParents] = useState<EntiteAdministrativeDto[]>([]);
    const [chefs, setChefs] = useState<UtilisateurDto[]>([]);

    const [utilisateurs, setUtilisateurs] = useState<UtilisateurDto>(new UtilisateurDto());

    const genderCollaborateurService = new GenderCollaborateurService();
    const utilisateurCollaborateurService = new UtilisateurCollaborateurService();
    const entiteAdministrativeTypeCollaborateurService = new EntiteAdministrativeTypeCollaborateurService();
    useEffect(() => {
        service.getList().then(({data}) => setEntiteAdministrativeParents(data)).catch(error => console.log(error));
        utilisateurCollaborateurService.getList().then(({data}) => setChefs(data)).catch(error => console.log(error));
        entiteAdministrativeTypeCollaborateurService.getList().then(({data}) => setEntiteAdministrativeTypes(data)).catch(error => console.log(error));

        genderCollaborateurService.getList().then(({data}) => setGenders(data)).catch(error => console.log(error));


    }, []);




    const addUtilisateurs = () => {
        setSubmitted(true);
        if( item.utilisateurs == null )
        item.utilisateurs = new Array<UtilisateurDto>();
        let _item = utilisateurs;
        if (!_item.id) {
            item.utilisateurs.push(_item);
            MessageService.showSuccess(showToast, 'Utilisateurs Created');
            setItem((prevState :any) => ({...prevState, utilisateurs: item.utilisateurs }));
        } else {
            const updatedItems = item.utilisateurs.map((item) => item.id === utilisateurs.id ? {...utilisateurs} : item);
            MessageService.showSuccess(showToast,'Utilisateurs Updated');
            setItem((prevState :any) => ({ ...prevState, utilisateurs: updatedItems}));
        }
        setUtilisateurs(new UtilisateurDto());
    };

    const deleteUtilisateurs = (rowData: any) => {
        const updatedItems = item.utilisateurs.filter((val) => val !== rowData);
        setItem((prevState ) => ({...prevState,utilisateurs: updatedItems }));
        setUtilisateurs(new UtilisateurDto());
        MessageService.showSuccess(showToast, 'EntiteAdministrativeItem Deleted');
    };

    const editUtilisateurs = (rowData: any) => {
         setActiveTab(0);
         setUtilisateurs(rowData);

    };

    const onInputNumerChangeUtilisateurs = (e: any, name: string) => {
         const val = e.value || 0;
         setUtilisateurs((prevUtilisateurs) => ({...prevUtilisateurs, [name]: val, }));
    };
    const onDropdownChangeUtilisateurs = (e: any, field: string) => {
        setUtilisateurs((prevState) => ({ ...prevState, [field]: e.value}));
    };

    const onBooleanInputChangeUtilisateurs = (e: InputSwitchChangeEvent, name: string) => {
       const val = e.value;
       setUtilisateurs((prevItem) => ({ ...prevItem, [name]: val, }));
    };

    const onInputDateChangeUtilisateurs = (e: CalendarChangeEvent, name: string) => {
        const val = e.value || '';
        setUtilisateurs({ ...utilisateurs, [name]:val})
    };

    const onInputTextChangeUtilisateurs = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>, name: string) => {
        const val = (e.target && e.target.value) || '';
        setUtilisateurs({ ...utilisateurs, [name]:val})
    };




    const itemDialogFooter = ( <>
        <Button label={t("cancel")} icon="pi pi-times" text onClick={hideDialog} />
        <Button label={t("save")} icon="pi pi-check" onClick={saveItem} /> </>
    );

return(
        <Dialog visible={visible} style={{width: '70vw'}} header={t("entiteAdministrative.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog} >
        <TabView activeIndex={activeIndex} onTabChange={onTabChange}>
            <TabPanel header={t("entiteAdministrative.tabPan")}>
                <div className="formgrid grid">
                    <div className="field col-6">
                        <label htmlFor="code">{t("entiteAdministrative.code")}</label>
                        <InputText id="code" value={item.code} onChange={(e) => onInputTextChange(e, 'code')} required className={classNames({'p-invalid': submitted && !item.code})} />
                        {submitted && !item.code && <small className="p-invalid">Code is required.</small>}
                    </div>
                    <div className="field col-5">
                        <label htmlFor="entiteAdministrativeParent">{t("entiteAdministrative.entiteAdministrativeParent")}</label>
                        <Dropdown  id="entiteAdministrativeParentDropdown"  value={item.entiteAdministrativeParent} options={entiteAdministrativeParents} onChange={(e) => onDropdownChange(e, 'entiteAdministrativeParent')}   placeholder={t("entiteAdministrative.entiteAdministrativeParentPlaceHolder")} filter filterPlaceholder={t("entiteAdministrative.entiteAdministrativeParentPlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="referenceGed">{t("entiteAdministrative.referenceGed")}</label>
                        <InputText id="referenceGed" value={item.referenceGed} onChange={(e) => onInputTextChange(e, 'referenceGed')} required className={classNames({'p-invalid': submitted && !item.referenceGed})} />
                        {submitted && !item.referenceGed && <small className="p-invalid">ReferenceGed is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="description">{t("entiteAdministrative.description")}</label>
                        <span className="p-float-label">
                        <InputTextarea id="description" value={item.description} onChange={(e) => onInputTextChange(e, 'description')} rows={5} cols={30}/>
                    </span>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="libelle">{t("entiteAdministrative.libelle")}</label>
                        <InputText id="libelle" value={item.libelle} onChange={(e) => onInputTextChange(e, 'libelle')} required className={classNames({'p-invalid': submitted && !item.libelle})} />
                        {submitted && !item.libelle && <small className="p-invalid">Libelle is required.</small>}
                    </div>
                    <div className="field col-5">
                        <label htmlFor="chef">{t("entiteAdministrative.chef")}</label>
                        <Dropdown  id="chefDropdown"  value={item.chef} options={chefs} onChange={(e) => onDropdownChange(e, 'chef')}   placeholder={t("entiteAdministrative.chefPlaceHolder")} filter filterPlaceholder={t("entiteAdministrative.chefPlaceHolderFilter")} optionLabel="nom" showClear/>
                    </div>
                    <div className="field col-5">
                        <label htmlFor="entiteAdministrativeType">{t("entiteAdministrative.entiteAdministrativeType")}</label>
                        <Dropdown  id="entiteAdministrativeTypeDropdown"  value={item.entiteAdministrativeType} options={entiteAdministrativeTypes} onChange={(e) => onDropdownChange(e, 'entiteAdministrativeType')}   placeholder={t("entiteAdministrative.entiteAdministrativeTypePlaceHolder")} filter filterPlaceholder={t("entiteAdministrative.entiteAdministrativeTypePlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                </div>
            </TabPanel>
            <TabPanel header={t("entiteAdministrative.utilisateurs")}>
                <TabView activeIndex={activeTab} onTabChange={(e) => setActiveTab(e.index)}>
                    <TabPanel header={t("creation")}>
                        <div className="grid">
                            <div className="field col-6">
                                <label htmlFor="email">{t("utilisateur.email")}</label>
                                <InputText id="email" value={utilisateurs.email} onChange={(e) => onInputTextChangeUtilisateurs(e, 'email')} required className={classNames({'p-invalid': submitted && !item.utilisateurs})}/>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="telephone">{t("utilisateur.telephone")}</label>
                                <InputText id="telephone" value={utilisateurs.telephone} onChange={(e) => onInputTextChangeUtilisateurs(e, 'telephone')} required className={classNames({'p-invalid': submitted && !item.utilisateurs})}/>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="nom">{t("utilisateur.nom")}</label>
                                <InputText id="nom" value={utilisateurs.nom} onChange={(e) => onInputTextChangeUtilisateurs(e, 'nom')} required className={classNames({'p-invalid': submitted && !item.utilisateurs})}/>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="prenom">{t("utilisateur.prenom")}</label>
                                <InputText id="prenom" value={utilisateurs.prenom} onChange={(e) => onInputTextChangeUtilisateurs(e, 'prenom')} required className={classNames({'p-invalid': submitted && !item.utilisateurs})}/>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="dateNaissance">{t("utilisateur.dateNaissance")}</label>
                                <Calendar id="dateNaissance" value={utilisateurs.dateNaissance}  onChange={(e) => onInputDateChangeUtilisateurs(e, 'dateNaissance')} dateFormat="dd/mm/yy"  showIcon={true} />
                            </div>
                            <div className="field col-5">
                                <label htmlFor="gender">{t("utilisateur.gender")}</label>
                                <Dropdown id="genderDropdown" value={utilisateurs.gender} options={genders} onChange={(e) => onDropdownChangeUtilisateurs(e, 'gender')}    placeholder={t("utilisateur.genderPlaceHolder")} filter filterPlaceholder={t("utilisateur.genderPlaceHolderFilter")}  optionLabel="libelle" showClear />
                             </div>
                            <div className="field col-6">
                                <label htmlFor="credentialsNonExpired">{t("utilisateur.credentialsNonExpired")}</label>
                                <span className="p-float-label">
                                <InputSwitch  id="credentialsNonExpired" checked={utilisateurs.credentialsNonExpired} onChange={(e) => onBooleanInputChangeUtilisateurs(e, 'credentialsNonExpired')} />
                            </span>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="enabled">{t("utilisateur.enabled")}</label>
                                <span className="p-float-label">
                                <InputSwitch  id="enabled" checked={utilisateurs.enabled} onChange={(e) => onBooleanInputChangeUtilisateurs(e, 'enabled')} />
                            </span>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="accountNonExpired">{t("utilisateur.accountNonExpired")}</label>
                                <span className="p-float-label">
                                <InputSwitch  id="accountNonExpired" checked={utilisateurs.accountNonExpired} onChange={(e) => onBooleanInputChangeUtilisateurs(e, 'accountNonExpired')} />
                            </span>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="accountNonLocked">{t("utilisateur.accountNonLocked")}</label>
                                <span className="p-float-label">
                                <InputSwitch  id="accountNonLocked" checked={utilisateurs.accountNonLocked} onChange={(e) => onBooleanInputChangeUtilisateurs(e, 'accountNonLocked')} />
                            </span>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="passwordChanged">{t("utilisateur.passwordChanged")}</label>
                                <span className="p-float-label">
                                <InputSwitch  id="passwordChanged" checked={utilisateurs.passwordChanged} onChange={(e) => onBooleanInputChangeUtilisateurs(e, 'passwordChanged')} />
                            </span>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="username">{t("utilisateur.username")}</label>
                                <InputText id="username" value={utilisateurs.username} onChange={(e) => onInputTextChangeUtilisateurs(e, 'username')} required className={classNames({'p-invalid': submitted && !item.utilisateurs})}/>
                            </div>
                            <div className="field col-6">
                                <label htmlFor="password">{t("utilisateur.password")}</label>
                                <InputText id="password" value={utilisateurs.password} onChange={(e) => onInputTextChangeUtilisateurs(e, 'password')} required className={classNames({'p-invalid': submitted && !item.utilisateurs})}/>
                            </div>
                            <div className="field col-1">
                                <Button icon="pi pi-plus" label="OK" className="mt-4" onClick={addUtilisateurs} />
                            </div>
                        </div>
                    </TabPanel>
                    <TabPanel header={t("list")}>
                    <div className="card">
                    <DataTable value={item.utilisateurs} tableStyle={{minWidth: '50rem'}} dataKey="id">
                        <Column field="email" header={t("utilisateur.email")} ></Column>
                        <Column field="telephone" header={t("utilisateur.telephone")} ></Column>
                        <Column field="nom" header={t("utilisateur.nom")} ></Column>
                        <Column field="prenom" header={t("utilisateur.prenom")} ></Column>
                        <Column field="dateNaissance" header={t("utilisateur.dateNaissance")} body={formateDate("dateNaissance")}></Column>
                        <Column field="gender.libelle" header={t("utilisateur.gender")}></Column>
                        <Column field="credentialsNonExpired" header={t("utilisateur.credentialsNonExpired")} ></Column>
                        <Column field="enabled" header={t("utilisateur.enabled")} ></Column>
                        <Column field="accountNonExpired" header={t("utilisateur.accountNonExpired")} ></Column>
                        <Column field="accountNonLocked" header={t("utilisateur.accountNonLocked")} ></Column>
                        <Column field="passwordChanged" header={t("utilisateur.passwordChanged")} ></Column>
                        <Column field="username" header={t("utilisateur.username")} ></Column>
                        <Column field="password" header={t("utilisateur.password")} ></Column>
                        <Column header={t("actions")} body={(rowData)=> (<div>
                        <Button icon="pi pi-times" rounded severity="warning" className="mr-2 p-button-danger" onClick={()=> deleteUtilisateurs(rowData)} />
                        <Button icon="pi pi-pencil" rounded severity="success" className="mr-2" onClick={()=> editUtilisateurs(rowData)} /> </div>)}></Column>
                    </DataTable>
                    </div>
                    </TabPanel>
                </TabView>
            </TabPanel>
        </TabView>
    </Dialog>
);
};
export default Create;
