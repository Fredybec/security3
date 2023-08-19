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

import  {DocumentDto}  from 'app/controller/model/Document.model';

type DocumentViewAdminType = {
    visible: boolean,
    onClose: () => void,
    selectedItem: DocumentDto,
    t: TFunction
}

const View: React.FC<DocumentViewAdminType> = ({visible,onClose,selectedItem, t}) => {

    const {
    onTabChange,
    hideDialog,
    itemDialogFooter,
    formateDate,
    parse,
    parseToIsoFormat,
    adaptDate,
    activeIndex
    } = useViewHook<DocumentDto>({selectedItem, onClose})

    const handleDownload  = () => {
        service.handleDownload();
    }
        return(
<Dialog visible={visible} style={{width: '70vw'}} header={t("document.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog} >
<TabView activeIndex={activeIndex} onTabChange={onTabChange}>
<TabPanel header={t("document.tabPan")}>
    <div className="formgrid grid">

            <div className="field col-6">
                <label htmlFor="reference">{t("document.reference")}</label>
                <InputText id="reference" value={selectedItem?.reference} disabled   />
            </div>

        <div className="field col-6">
            <label htmlFor="referenceGed">{t("document.referenceGed")}</label>
            <Button label="Download" onClick={handleDownload} />
        </div>

        <div className="field col-6">
            <label htmlFor="uploadDate">{t("document.uploadDate")}</label>
            <Calendar id="uploadDate" value={adaptDate(selectedItem?.uploadDate)} disabled dateFormat="dd/mm/yy" showIcon={true}  />
        </div>

                <div className="field col-6">
                    <label htmlFor="annee">{t("document.annee")}</label>
                    <InputNumber id="annee" value={selectedItem.annee} disabled/>
                </div>

                <div className="field col-6">
                    <label htmlFor="semstre">{t("document.semstre")}</label>
                    <InputNumber id="semstre" value={selectedItem.semstre} disabled/>
                </div>

                <div className="field col-6">
                    <label htmlFor="mois">{t("document.mois")}</label>
                    <InputNumber id="mois" value={selectedItem.mois} disabled/>
                </div>

                <div className="field col-6">
                    <label htmlFor="jour">{t("document.jour")}</label>
                    <InputNumber id="jour" value={selectedItem.jour} disabled/>
                </div>

        <div className="field col-6">
            <div  className="label-inputswitch">
                    <label htmlFor="ocr">{t("document.ocr")}</label>
                    <span className="p-float-label">
                        <InputSwitch  id="ocr" checked={selectedItem?.ocr} disabled />
                    </span>
            </div>
            </div>

            <div className="field col-6">
                <label htmlFor="content">{t("document.content")}</label>
                <span className="p-float-label">
                   <InputTextarea id="content" value={selectedItem?.content} disabled rows={5} cols={30} />
                </span>
            </div>

                <div className="field col-6">
                    <label htmlFor="size">{t("document.size")}</label>
                    <InputNumber id="size" value={selectedItem.size} disabled/>
                </div>

                <div className="field col-6">
                    <label htmlFor="documentType">{t("document.documentType")}</label>
                    <InputText  id="documentTypeDropdown"  value={selectedItem?.documentType?.libelle}  disabled  />
                </div>
                <div className="field col-6">
                    <label htmlFor="documentState">{t("document.documentState")}</label>
                    <InputText  id="documentStateDropdown"  value={selectedItem?.documentState?.libelle}  disabled  />
                </div>
                <div className="field col-6">
                    <label htmlFor="documentCategorie">{t("document.documentCategorie")}</label>
                    <InputText  id="documentCategorieDropdown"  value={selectedItem?.documentCategorie?.libelle}  disabled  />
                </div>
            <div className="field col-6">
                <label htmlFor="description">{t("document.description")}</label>
                <span className="p-float-label">
                   <InputTextarea id="description" value={selectedItem?.description} disabled rows={5} cols={30} />
                </span>
            </div>

                <div className="field col-6">
                    <label htmlFor="utilisateur">{t("document.utilisateur")}</label>
                    <InputText  id="utilisateurDropdown"  value={selectedItem?.utilisateur?.nom}  disabled  />
                </div>
        <div className="field col-6">
            <div  className="label-inputswitch">
                    <label htmlFor="archive">{t("document.archive")}</label>
                    <span className="p-float-label">
                        <InputSwitch  id="archive" checked={selectedItem?.archive} disabled />
                    </span>
            </div>
            </div>

        <div className="field col-6">
            <div  className="label-inputswitch">
                    <label htmlFor="versionne">{t("document.versionne")}</label>
                    <span className="p-float-label">
                        <InputSwitch  id="versionne" checked={selectedItem?.versionne} disabled />
                    </span>
            </div>
            </div>

                <div className="field col-6">
                    <label htmlFor="entiteAdministrative">{t("document.entiteAdministrative")}</label>
                    <InputText  id="entiteAdministrativeDropdown"  value={selectedItem?.entiteAdministrative?.libelle}  disabled  />
                </div>
                <div className="field col-6">
                    <label htmlFor="documentCategorieModel">{t("document.documentCategorieModel")}</label>
                    <InputText  id="documentCategorieModelDropdown"  value={selectedItem?.documentCategorieModel?.libelle}  disabled  />
                </div>
        </div>
</TabPanel>
    <TabPanel header={t("document.documentIndexElements")}>
                <div className="card">
                    <DataTable value={selectedItem?.documentIndexElements} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="indexElement.libelle" header={t("documentIndexElement.indexElement")}></Column>
                                <Column field="value" header={t("documentIndexElement.value")}   ></Column>
                                <Column field="description" header={t("documentIndexElement.description")}   ></Column>
                    </DataTable>
                </div>
        </TabPanel>
    <TabPanel header={t("document.documentPartageGroupes")}>
                <div className="card">
                    <DataTable value={selectedItem?.documentPartageGroupes} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="groupe.libelle" header={t("documentPartageGroupe.groupe")}></Column>
                                <Column field="dateShare" header={t("documentPartageGroupe.dateShare")}  body={formateDate("dateShare")} ></Column>
                                <Column field="accessShare.libelle" header={t("documentPartageGroupe.accessShare")}></Column>
                                <Column field="description" header={t("documentPartageGroupe.description")}   ></Column>
                    </DataTable>
                </div>
        </TabPanel>
    <TabPanel header={t("document.documentPartageUtilisateurs")}>
                <div className="card">
                    <DataTable value={selectedItem?.documentPartageUtilisateurs} tableStyle={{minWidth: '50rem'}} dataKey="id">
                                <Column field="utilisateur.nom" header={t("documentPartageUtilisateur.utilisateur")}></Column>
                                <Column field="dateShare" header={t("documentPartageUtilisateur.dateShare")}  body={formateDate("dateShare")} ></Column>
                                <Column field="accessShare.libelle" header={t("documentPartageUtilisateur.accessShare")}></Column>
                                <Column field="description" header={t("documentPartageUtilisateur.description")}   ></Column>
                    </DataTable>
                </div>
        </TabPanel>
</TabView>
</Dialog>
);
};
export default View;
