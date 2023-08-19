import {Column} from 'primereact/column';
import {TabPanel, TabView} from 'primereact/tabview';
import {DataTable} from 'primereact/datatable';
import {Dialog} from 'primereact/dialog';
import {InputNumber} from 'primereact/inputnumber';
import {InputText} from 'primereact/inputtext';
import {InputTextarea} from 'primereact/inputtextarea';
import React from 'react';
import {Calendar} from 'primereact/calendar';
import {InputSwitch} from 'primereact/inputswitch';
import {TFunction} from "i18next";
import useViewHook from "app/component/zyhook/useViewhook";

import  {EntiteAdministrativeDto}  from 'app/controller/model/EntiteAdministrative.model';

type EntiteAdministrativeViewAdminType = {
    visible: boolean,
    onClose: () => void,
    selectedItem: EntiteAdministrativeDto,
    t: TFunction
}

const View: React.FC<EntiteAdministrativeViewAdminType> = ({visible,onClose,selectedItem, t}) => {

    const {
    onTabChange,
    hideDialog,
    itemDialogFooter,
    formateDate,
    parse,
    parseToIsoFormat,
    adaptDate,
    activeIndex
    } = useViewHook<EntiteAdministrativeDto>({selectedItem, onClose})

        return(
<Dialog visible={visible} style={{width: '70vw'}} header={t("entiteAdministrative.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog} >
<TabView activeIndex={activeIndex} onTabChange={onTabChange}>
<TabPanel header={t("entiteAdministrative.tabPan")}>
    <div className="formgrid grid">

            <div className="field col-6">
                <label htmlFor="code">{t("entiteAdministrative.code")}</label>
                <InputText id="code" value={selectedItem?.code} disabled   />
            </div>

                <div className="field col-6">
                    <label htmlFor="entiteAdministrativeParent">{t("entiteAdministrative.entiteAdministrativeParent")}</label>
                    <InputText  id="entiteAdministrativeParentDropdown"  value={selectedItem?.entiteAdministrativeParent?.libelle}  disabled  />
                </div>
            <div className="field col-6">
                <label htmlFor="referenceGed">{t("entiteAdministrative.referenceGed")}</label>
                <InputText id="referenceGed" value={selectedItem?.referenceGed} disabled   />
            </div>

            <div className="field col-6">
                <label htmlFor="description">{t("entiteAdministrative.description")}</label>
                <span className="p-float-label">
                   <InputTextarea id="description" value={selectedItem?.description} disabled rows={5} cols={30} />
                </span>
            </div>

            <div className="field col-6">
                <label htmlFor="libelle">{t("entiteAdministrative.libelle")}</label>
                <InputText id="libelle" value={selectedItem?.libelle} disabled   />
            </div>

                <div className="field col-6">
                    <label htmlFor="chef">{t("entiteAdministrative.chef")}</label>
                    <InputText  id="chefDropdown"  value={selectedItem?.chef?.nom}  disabled  />
                </div>
                <div className="field col-6">
                    <label htmlFor="entiteAdministrativeType">{t("entiteAdministrative.entiteAdministrativeType")}</label>
                    <InputText  id="entiteAdministrativeTypeDropdown"  value={selectedItem?.entiteAdministrativeType?.libelle}  disabled  />
                </div>
        </div>
</TabPanel>
    <TabPanel header={t("entiteAdministrative.utilisateurs")}>
                <div className="card">
                    <DataTable value={selectedItem?.utilisateurs} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="email" header={t("utilisateur.email")}   ></Column>
                                <Column field="telephone" header={t("utilisateur.telephone")}   ></Column>
                                <Column field="nom" header={t("utilisateur.nom")}   ></Column>
                                <Column field="prenom" header={t("utilisateur.prenom")}   ></Column>
                                <Column field="dateNaissance" header={t("utilisateur.dateNaissance")}  body={formateDate("dateNaissance")} ></Column>
                                <Column field="gender.libelle" header={t("utilisateur.gender")}></Column>
                                <Column field="credentialsNonExpired" header={t("utilisateur.credentialsNonExpired")}   ></Column>
                                <Column field="enabled" header={t("utilisateur.enabled")}   ></Column>
                                <Column field="accountNonExpired" header={t("utilisateur.accountNonExpired")}   ></Column>
                                <Column field="accountNonLocked" header={t("utilisateur.accountNonLocked")}   ></Column>
                                <Column field="passwordChanged" header={t("utilisateur.passwordChanged")}   ></Column>
                                <Column field="username" header={t("utilisateur.username")}   ></Column>
                                <Column field="password" header={t("utilisateur.password")}   ></Column>
                    </DataTable>
                </div>
        </TabPanel>
</TabView>
</Dialog>
);
};
export default View;
