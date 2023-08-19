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

import  {DocumentCategorieModelDto}  from 'app/controller/model/DocumentCategorieModel.model';

type DocumentCategorieModelViewAdminType = {
    visible: boolean,
    onClose: () => void,
    selectedItem: DocumentCategorieModelDto,
    t: TFunction
}

const View: React.FC<DocumentCategorieModelViewAdminType> = ({visible,onClose,selectedItem, t}) => {

    const {
    onTabChange,
    hideDialog,
    itemDialogFooter,
    formateDate,
    parse,
    parseToIsoFormat,
    adaptDate,
    activeIndex
    } = useViewHook<DocumentCategorieModelDto>({selectedItem, onClose})

    const handleDownload  = () => {
        service.handleDownload();
    }
        return(
<Dialog visible={visible} style={{width: '70vw'}} header={t("documentCategorieModel.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog} >
<TabView activeIndex={activeIndex} onTabChange={onTabChange}>
<TabPanel header={t("documentCategorieModel.tabPan")}>
    <div className="formgrid grid">

            <div className="field col-6">
                <label htmlFor="code">{t("documentCategorieModel.code")}</label>
                <InputText id="code" value={selectedItem?.code} disabled   />
            </div>

            <div className="field col-6">
                <label htmlFor="libelle">{t("documentCategorieModel.libelle")}</label>
                <InputText id="libelle" value={selectedItem?.libelle} disabled   />
            </div>

        <div className="field col-6">
            <label htmlFor="referenceGed">{t("documentCategorieModel.referenceGed")}</label>
            <Button label="Download" onClick={handleDownload} />
        </div>

            <div className="field col-6">
                <label htmlFor="description">{t("documentCategorieModel.description")}</label>
                <span className="p-float-label">
                   <InputTextarea id="description" value={selectedItem?.description} disabled rows={5} cols={30} />
                </span>
            </div>

                <div className="field col-6">
                    <label htmlFor="documentCategorie">{t("documentCategorieModel.documentCategorie")}</label>
                    <InputText  id="documentCategorieDropdown"  value={selectedItem?.documentCategorie?.libelle}  disabled  />
                </div>
        </div>
</TabPanel>
</TabView>
</Dialog>
);
};
export default View;
