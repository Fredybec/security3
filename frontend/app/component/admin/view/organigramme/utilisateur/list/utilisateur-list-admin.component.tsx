import {Button} from 'primereact/button';
import {Column} from 'primereact/column';


import {DataTable} from 'primereact/datatable';
import {Dialog} from 'primereact/dialog';
import {FileUpload} from 'primereact/fileupload';
import {InputText} from 'primereact/inputtext';
import {Toast} from 'primereact/toast';
import {Toolbar} from 'primereact/toolbar';
import React, {useEffect, useRef, useState} from 'react';
import {Paginator, PaginatorPageChangeEvent} from 'primereact/paginator';
import {Card} from 'primereact/card';
import {Calendar} from 'primereact/calendar';
import {InputNumber} from 'primereact/inputnumber';
import {Dropdown} from 'primereact/dropdown';
import {format} from "date-fns";
import useListHook from "app/component/zyhook/useListhook";
import {MessageService} from 'app/zynerator/service/MessageService';


import {UtilisateurAdminService} from 'app/controller/service/admin/UtilisateurAdminService.service';
import {UtilisateurDto}  from 'app/controller/model/Utilisateur.model';
import {UtilisateurCriteria} from 'app/controller/criteria/UtilisateurCriteria.model';

import {GenderDto} from 'app/controller/model/Gender.model';
import {GenderAdminService} from 'app/controller/service/admin/GenderAdminService.service';
import {EntiteAdministrativeDto} from 'app/controller/model/EntiteAdministrative.model';
import {EntiteAdministrativeAdminService} from 'app/controller/service/admin/EntiteAdministrativeAdminService.service';

import { useTranslation } from 'react-i18next';

import Edit from '../edit/utilisateur-edit-admin.component';
import Create from '../create/utilisateur-create-admin.component';
import View from '../view/utilisateur-view-admin.component';


const List = () => {

    const { t } = useTranslation();

    const emptyItem = new UtilisateurDto();
    const emptyCriteria = new UtilisateurCriteria();
    const service = new UtilisateurAdminService();


    const {
        items,
        showSearch,
        deleteItemDialog,
        item,
        selectedItems,
        setSelectedItems,
        hideDeleteItemDialog,
        globalFilter,
        setGlobalFilter,
        showCreateDialog,
        setShowCreateDialog,
        showEditDialog,
        setShowEditDialog,
        showViewDialog,
        setShowViewDialog,
        selectedItem,
        setSelectedItem,
        rows,
        totalRecords,
        criteria,
        setCriteria,
        first,
        fetchItems,
        toast,
        dt,
        findByCriteriaShow,
        handleCancelClick,
        confirmDeleteSelected,
        exportCSV,
        deleteItem,
        deleteItemDialogFooter,
        leftToolbarTemplate,
        rightToolbarTemplate,
        actionBodyTemplate,
        CustomBooleanCell,
        handleValidateClick,
        onPage,
        showCreateModal,
        showEditModal,
        showViewModal,
        add,
        update,
        confirmDeleteItem,
        statusBodyTemplate,
        formateDate,
        deleteSelectedItems,
        deleteItemsDialog,
        deleteItemsDialogFooter,
        hideDeleteItemsDialog
    } = useListHook<UtilisateurDto, UtilisateurCriteria>({ emptyItem, emptyCriteria,service, t})



    const [genders, setGenders] = useState<GenderDto[]>([]);
    const [entiteAdministratives, setEntiteAdministratives] = useState<EntiteAdministrativeDto[]>([]);

    const genderAdminService = new GenderAdminService();
    const entiteAdministrativeAdminService = new EntiteAdministrativeAdminService();

    useEffect(() => {

        genderAdminService.getList().then(({data}) => setGenders(data)).catch(error => console.log(error));
        entiteAdministrativeAdminService.getList().then(({data}) => setEntiteAdministratives(data)).catch(error => console.log(error));
        fetchItems(criteria);
    }, []);



    const header = (
    <div className="flex flex-column md:flex-row md:justify-content-between md:align-items-center">
        <h5 className="m-0">{t("utilisateur.header")}</h5>
        <span className="block mt-2 md:mt-0 p-input-icon-left"><i className="pi pi-search"/>
            <InputText type="search" onInput={(e) => setGlobalFilter(e.currentTarget.value)}
                       placeholder={t("search")}/> </span>
    </div>
    );
    return (
    <div className="grid crud-demo">
        <div className="col-12">
            <div className="card">
                <Toast ref={toast} />
                <Toolbar className="mb-4" left={leftToolbarTemplate} right={rightToolbarTemplate}></Toolbar>
                {findByCriteriaShow && (
                <Card title={t("search")} className="mb-5">
                        <div className="grid">
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="1">{t("utilisateur.email")}</label>
                                <InputText id="1" value={criteria.email} onChange={(e) => setCriteria({ ...criteria, email: e.target.value })} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="2">{t("utilisateur.telephone")}</label>
                                <InputText id="2" value={criteria.telephone} onChange={(e) => setCriteria({ ...criteria, telephone: e.target.value })} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="3">{t("utilisateur.nom")}</label>
                                <InputText id="3" value={criteria.nom} onChange={(e) => setCriteria({ ...criteria, nom: e.target.value })} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="4">{t("utilisateur.prenom")}</label>
                                <InputText id="4" value={criteria.prenom} onChange={(e) => setCriteria({ ...criteria, prenom: e.target.value })} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="5-1">{t("utilisateur.dateNaissanceMin")}</label>
                                <Calendar id="5-1" value={criteria.dateNaissanceFrom} onChange={(e) => setCriteria({ ...criteria, dateNaissanceFrom: e.value as Date })} dateFormat="dd-MM-yy" showIcon={true} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="5-2">{t("utilisateur.dateNaissanceMax")}</label>
                                <Calendar id="5-2" value={criteria.dateNaissanceTo} onChange={(e) => setCriteria({ ...criteria, dateNaissanceTo: e.value as Date })} dateFormat="dd-MM-yy" showIcon={true} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="6">{t("utilisateur.genderPlaceHolder")}</label>
                                <Dropdown id="6" value={criteria.gender} options={genders} onChange={(e) => setCriteria({ ...criteria, gender: e.target.value })} optionLabel="libelle" filter showClear/>
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="7">{t("utilisateur.entiteAdministrativePlaceHolder")}</label>
                                <Dropdown id="7" value={criteria.entiteAdministrative} options={entiteAdministratives} onChange={(e) => setCriteria({ ...criteria, entiteAdministrative: e.target.value })} optionLabel="libelle" filter showClear/>
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="13">{t("utilisateur.username")}</label>
                                <InputText id="13" value={criteria.username} onChange={(e) => setCriteria({ ...criteria, username: e.target.value })} />
                            </div>
                            <div className="flex flex-column col-3">
                                <label className="mb-1"  htmlFor="14">{t("utilisateur.password")}</label>
                                <InputText id="14" value={criteria.password} onChange={(e) => setCriteria({ ...criteria, password: e.target.value })} />
                            </div>
                        </div>
                        <div style={{ marginTop : '1rem', display: 'flex', justifyContent: 'flex-end' }} >
                            <Button label={t("validate")} icon="pi pi-sort-amount-down" className="p-button-info mr-2" onClick={handleValidateClick} />
                            <Button label={t("cancel")} className="p-button-secondary mr-2"  icon="pi pi-times" onClick={handleCancelClick} />
                        </div>
                </Card>
                )}
                <DataTable ref={dt} value={items} selection={selectedItems} onSelectionChange={(e) => setSelectedItems(e.value as UtilisateurDto[])} dataKey="id" className="datatable-responsive" globalFilter={globalFilter} header={header} responsiveLayout="scroll" >
                    <Column selectionMode="multiple" headerStyle={{ width: '4rem' }}> </Column>
                    
                    <Column field="email" header={t("utilisateur.email")} sortable></Column>
                    
                    
                    <Column field="telephone" header={t("utilisateur.telephone")} sortable></Column>
                    
                    
                    <Column field="nom" header={t("utilisateur.nom")} sortable></Column>
                    
                    
                    <Column field="prenom" header={t("utilisateur.prenom")} sortable></Column>
                    
                    
                    <Column field="dateNaissance" header={t("utilisateur.dateNaissance")} sortable body={formateDate("dateNaissance")}></Column>
                    
                    
                    <Column field="gender.libelle" header={t("utilisateur.gender")} sortable ></Column>
                    
                    
                    <Column field="entiteAdministrative.libelle" header={t("utilisateur.entiteAdministrative")} sortable ></Column>
                    
                    
                    <Column field="credentialsNonExpired" header={t("utilisateur.credentialsNonExpired")} body={CustomBooleanCell("credentialsNonExpired")} sortable></Column>
                    
                    
                    <Column field="enabled" header={t("utilisateur.enabled")} body={CustomBooleanCell("enabled")} sortable></Column>
                    
                     {/* 
                    <Column field="accountNonExpired" header={t("utilisateur.accountNonExpired")} body={CustomBooleanCell("accountNonExpired")} sortable></Column>
                     */} 
                     {/* 
                    <Column field="accountNonLocked" header={t("utilisateur.accountNonLocked")} body={CustomBooleanCell("accountNonLocked")} sortable></Column>
                     */} 
                     {/* 
                    <Column field="passwordChanged" header={t("utilisateur.passwordChanged")} body={CustomBooleanCell("passwordChanged")} sortable></Column>
                     */} 
                     {/* 
                    <Column field="username" header={t("utilisateur.username")} sortable></Column>
                     */} 
                     {/* 
                    <Column field="password" header={t("utilisateur.password")} sortable></Column>
                     */} 
                    <Column header={t("actions")} body={actionBodyTemplate}></Column>
                </DataTable>
                <div className="p-d-flex p-ai-center p-jc-between">
                    <Paginator onPageChange={onPage} first={first} rows={rows} totalRecords={totalRecords} />
                </div>
                {showCreateDialog && <Create visible={showCreateDialog} onClose={() => setShowCreateDialog(false)} add={add} showToast={toast} list={items} service={service} t={t} />}

                {showEditDialog && <Edit  visible={showEditDialog} onClose={() =>  { setShowEditDialog(false); setSelectedItem(emptyItem); }} showToast={toast} selectedItem={selectedItem} update={update} list={items} service={service}   t={t} />}

                {showViewDialog && <View visible={showViewDialog} onClose={() =>  { setShowViewDialog(false); setSelectedItem(emptyItem); }} selectedItem={selectedItem}   t={t} />}
                <Dialog visible={deleteItemDialog} style={{width: '450px'}} header={t("confirm")} modal footer={deleteItemDialogFooter} onHide={hideDeleteItemDialog}>
                    <div className="flex align-items-center justify-content-center">
                    <i className="pi pi-exclamation-triangle mr-3" style={{fontSize: '2rem'}}/>
                    {item && (<span>{t("utilisateur.deleteUtilisateurConfirmationMessage")} <b>{item.nom}</b>?</span>)}
                    </div>
                </Dialog>

            <Dialog visible={deleteItemsDialog} style={{ width: '450px' }} header="Confirm" modal footer={deleteItemsDialogFooter} onHide={hideDeleteItemsDialog} >
                <div className="flex align-items-center justify-content-center">
                    <i className="pi pi-exclamation-triangle mr-3" style={{ fontSize: '2rem' }} />
                    {item && <span>{t("utilisateur.deleteUtilisateursConfirmationMessage")}</span>}
                </div>
            </Dialog>

            </div>
        </div>
    </div>
);
};
export default List;

