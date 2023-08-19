import {Button} from 'primereact/button';
import {Column} from 'primereact/column';
import {TabView, TabPanel} from 'primereact/tabview';
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

import {RoleDto} from "app/zynerator/dto/RoleDto.model";
import RoleService from "app/zynerator/service/RoleService";
import {UtilisateurCollaborateurService} from 'app/controller/service/collaborateur/UtilisateurCollaborateurService.service';
import  {UtilisateurDto}  from 'app/controller/model/Utilisateur.model';
import {UtilisateurCriteria} from "app/controller/criteria/UtilisateurCriteria.model";

import {EntiteAdministrativeDto} from 'app/controller/model/EntiteAdministrative.model';
import {EntiteAdministrativeCollaborateurService} from 'app/controller/service/collaborateur/EntiteAdministrativeCollaborateurService.service';
import {GenderDto} from 'app/controller/model/Gender.model';
import {GenderCollaborateurService} from 'app/controller/service/collaborateur/GenderCollaborateurService.service';
import {TFunction} from "i18next";
import {Toast} from "primereact/toast";
import useCreateHook from "app/component/zyhook/useCreate.hook";



type UtilisateurCreateCollaborateurType = {
    visible: boolean,
    onClose: () => void,
    add: (item: UtilisateurDto) => void,
    showToast: React.Ref<Toast>,
    list: UtilisateurDto[],
    service: UtilisateurCollaborateurService,
    t: TFunction
}
const Create: React.FC<UtilisateurCreateCollaborateurType> = ({visible, onClose, add, showToast, list, service, t}) => {


    const isFormValid = () => {
    let errorMessages = new Array<string>();
                if(item.email == '')
                errorMessages.push("email is required")
                if(item.nom == '')
                errorMessages.push("nom is required")
        return errorMessages.length == 0 ;
    }
    const emptyItem = new UtilisateurDto();
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
        } = useCreateHook<UtilisateurDto, UtilisateurCriteria>({list, emptyItem, onClose, add, showToast,service, isFormValid})
    const [roles, setRoles] = useState<RoleDto[]>([]);
    const [entiteAdministratives, setEntiteAdministratives] = useState<EntiteAdministrativeDto[]>([]);
    const [genders, setGenders] = useState<GenderDto[]>([]);


    const entiteAdministrativeCollaborateurService = new EntiteAdministrativeCollaborateurService();
    const genderCollaborateurService = new GenderCollaborateurService();
    const roleService = new RoleService();
    useEffect(() => {
        genderCollaborateurService.getList().then(({data}) => setGenders(data)).catch(error => console.log(error));
        entiteAdministrativeCollaborateurService.getList().then(({data}) => setEntiteAdministratives(data)).catch(error => console.log(error));
        roleService.getList().then(({data}) => setRoles(data)).catch(error => console.log(error));
    }, []);








    const itemDialogFooter = ( <>
        <Button label={t("cancel")} icon="pi pi-times" text onClick={hideDialog} />
        <Button label={t("save")} icon="pi pi-check" onClick={saveItem} /> </>
    );

return(
        <Dialog visible={visible} style={{width: '70vw'}} header={t("utilisateur.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog} >
        <TabView activeIndex={activeIndex} onTabChange={onTabChange}>
            <TabPanel header={t("utilisateur.tabPan")}>
                <div className="formgrid grid">
                    <div className="field col-6">
                        <label htmlFor="email">{t("utilisateur.email")}</label>
                        <InputText id="email" value={item.email} onChange={(e) => onInputTextChange(e, 'email')} required className={classNames({'p-invalid': submitted && !item.email})} />
                        {submitted && !item.email && <small className="p-invalid">Email is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="telephone">{t("utilisateur.telephone")}</label>
                        <InputText id="telephone" value={item.telephone} onChange={(e) => onInputTextChange(e, 'telephone')} required className={classNames({'p-invalid': submitted && !item.telephone})} />
                        {submitted && !item.telephone && <small className="p-invalid">Telephone is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="nom">{t("utilisateur.nom")}</label>
                        <InputText id="nom" value={item.nom} onChange={(e) => onInputTextChange(e, 'nom')} required className={classNames({'p-invalid': submitted && !item.nom})} />
                        {submitted && !item.nom && <small className="p-invalid">Nom is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="prenom">{t("utilisateur.prenom")}</label>
                        <InputText id="prenom" value={item.prenom} onChange={(e) => onInputTextChange(e, 'prenom')} required className={classNames({'p-invalid': submitted && !item.prenom})} />
                        {submitted && !item.prenom && <small className="p-invalid">Prenom is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="dateNaissance">{t("utilisateur.dateNaissance")}</label>
                        <Calendar id="dateNaissance" value={item.dateNaissance} onChange={(e) => onInputDateChange(e, 'dateNaissance')} dateFormat="dd/mm/yy"  showIcon={true} />
                    </div>
                    <div className="field col-5">
                        <label htmlFor="gender">{t("utilisateur.gender")}</label>
                        <Dropdown  id="genderDropdown"  value={item.gender} options={genders} onChange={(e) => onDropdownChange(e, 'gender')}   placeholder={t("utilisateur.genderPlaceHolder")} filter filterPlaceholder={t("utilisateur.genderPlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                    <div className="field col-5">
                        <label htmlFor="entiteAdministrative">{t("utilisateur.entiteAdministrative")}</label>
                        <Dropdown  id="entiteAdministrativeDropdown"  value={item.entiteAdministrative} options={entiteAdministratives} onChange={(e) => onDropdownChange(e, 'entiteAdministrative')}   placeholder={t("utilisateur.entiteAdministrativePlaceHolder")} filter filterPlaceholder={t("utilisateur.entiteAdministrativePlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                    <div className="field col-6">
                    <div  className="label-inputswitch">
                        <label htmlFor="credentialsNonExpired">{t("utilisateur.credentialsNonExpired")}</label>
                        <span className="p-float-label">
                        <InputSwitch  id="credentialsNonExpired" checked={item.credentialsNonExpired} onChange={(e) => onBooleanInputChange(e, 'credentialsNonExpired')} />
                        </span>
                    </div>
                    </div>
                    <div className="field col-6">
                    <div  className="label-inputswitch">
                        <label htmlFor="enabled">{t("utilisateur.enabled")}</label>
                        <span className="p-float-label">
                        <InputSwitch  id="enabled" checked={item.enabled} onChange={(e) => onBooleanInputChange(e, 'enabled')} />
                        </span>
                    </div>
                    </div>
                    <div className="field col-6">
                    <div  className="label-inputswitch">
                        <label htmlFor="accountNonExpired">{t("utilisateur.accountNonExpired")}</label>
                        <span className="p-float-label">
                        <InputSwitch  id="accountNonExpired" checked={item.accountNonExpired} onChange={(e) => onBooleanInputChange(e, 'accountNonExpired')} />
                        </span>
                    </div>
                    </div>
                    <div className="field col-6">
                    <div  className="label-inputswitch">
                        <label htmlFor="accountNonLocked">{t("utilisateur.accountNonLocked")}</label>
                        <span className="p-float-label">
                        <InputSwitch  id="accountNonLocked" checked={item.accountNonLocked} onChange={(e) => onBooleanInputChange(e, 'accountNonLocked')} />
                        </span>
                    </div>
                    </div>
                    <div className="field col-6">
                    <div  className="label-inputswitch">
                        <label htmlFor="passwordChanged">{t("utilisateur.passwordChanged")}</label>
                        <span className="p-float-label">
                        <InputSwitch  id="passwordChanged" checked={item.passwordChanged} onChange={(e) => onBooleanInputChange(e, 'passwordChanged')} />
                        </span>
                    </div>
                    </div>
                    <div className="field col-6">
                        <label htmlFor="username">{t("utilisateur.username")}</label>
                        <InputText id="username" value={item.username} onChange={(e) => onInputTextChange(e, 'username')} required className={classNames({'p-invalid': submitted && !item.username})} />
                        {submitted && !item.username && <small className="p-invalid">Username is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="password">{t("utilisateur.password")}</label>
                        <InputText id="password" value={item.password} onChange={(e) => onInputTextChange(e, 'password')} required className={classNames({'p-invalid': submitted && !item.password})} />
                        {submitted && !item.password && <small className="p-invalid">Password is required.</small>}
                    </div>
                    <div className="field col-6">
                        <label htmlFor="roles">Roles</label>
                        <MultiSelect value={item.roles} options={roles} optionLabel="label" display="chip"
                                     placeholder="select roles" maxSelectedLabels={1}
                                     onChange={(e) => onMultiSelectChange(e, 'roles')}/>
                    </div>
                </div>
            </TabPanel>
        </TabView>
    </Dialog>
);
};
export default Create;
