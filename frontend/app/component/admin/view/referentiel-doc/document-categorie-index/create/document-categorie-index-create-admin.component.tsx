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

import {DocumentCategorieIndexAdminService} from 'app/controller/service/admin/DocumentCategorieIndexAdminService.service';
import  {DocumentCategorieIndexDto}  from 'app/controller/model/DocumentCategorieIndex.model';
import {DocumentCategorieIndexCriteria} from "app/controller/criteria/DocumentCategorieIndexCriteria.model";

import {IndexElementDto} from 'app/controller/model/IndexElement.model';
import {IndexElementAdminService} from 'app/controller/service/admin/IndexElementAdminService.service';
import {DocumentCategorieDto} from 'app/controller/model/DocumentCategorie.model';
import {DocumentCategorieAdminService} from 'app/controller/service/admin/DocumentCategorieAdminService.service';
import {DocumentCategorieIndexRuleDto} from 'app/controller/model/DocumentCategorieIndexRule.model';
import {DocumentCategorieIndexRuleAdminService} from 'app/controller/service/admin/DocumentCategorieIndexRuleAdminService.service';
import {TFunction} from "i18next";
import {Toast} from "primereact/toast";
import useCreateHook from "app/component/zyhook/useCreate.hook";



type DocumentCategorieIndexCreateAdminType = {
    visible: boolean,
    onClose: () => void,
    add: (item: DocumentCategorieIndexDto) => void,
    showToast: React.Ref<Toast>,
    list: DocumentCategorieIndexDto[],
    service: DocumentCategorieIndexAdminService,
    t: TFunction
}
const Create: React.FC<DocumentCategorieIndexCreateAdminType> = ({visible, onClose, add, showToast, list, service, t}) => {


    const isFormValid = () => {
    let errorMessages = new Array<string>();
        return errorMessages.length == 0 ;
    }
    const emptyItem = new DocumentCategorieIndexDto();
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
        } = useCreateHook<DocumentCategorieIndexDto, DocumentCategorieIndexCriteria>({list, emptyItem, onClose, add, showToast,service, isFormValid})
    const [indexElements, setIndexElements] = useState<IndexElementDto[]>([]);
    const [documentCategories, setDocumentCategories] = useState<DocumentCategorieDto[]>([]);
    const [documentCategorieIndexRules, setDocumentCategorieIndexRules] = useState<DocumentCategorieIndexRuleDto[]>([]);


    const indexElementAdminService = new IndexElementAdminService();
    const documentCategorieAdminService = new DocumentCategorieAdminService();
    const documentCategorieIndexRuleAdminService = new DocumentCategorieIndexRuleAdminService();
    useEffect(() => {
        indexElementAdminService.getList().then(({data}) => setIndexElements(data)).catch(error => console.log(error));
        documentCategorieAdminService.getList().then(({data}) => setDocumentCategories(data)).catch(error => console.log(error));
        documentCategorieIndexRuleAdminService.getList().then(({data}) => setDocumentCategorieIndexRules(data)).catch(error => console.log(error));
    }, []);








    const itemDialogFooter = ( <>
        <Button label={t("cancel")} icon="pi pi-times" text onClick={hideDialog} />
        <Button label={t("save")} icon="pi pi-check" onClick={saveItem} /> </>
    );

return(
        <Dialog visible={visible} style={{width: '70vw'}} header={t("documentCategorieIndex.tabPan")} modal className="p-fluid" footer={itemDialogFooter} onHide={hideDialog} >
        <TabView activeIndex={activeIndex} onTabChange={onTabChange}>
            <TabPanel header={t("documentCategorieIndex.tabPan")}>
                <div className="formgrid grid">
                    <div className="field col-5">
                        <label htmlFor="indexElement">{t("documentCategorieIndex.indexElement")}</label>
                        <Dropdown  id="indexElementDropdown"  value={item.indexElement} options={indexElements} onChange={(e) => onDropdownChange(e, 'indexElement')}   placeholder={t("documentCategorieIndex.indexElementPlaceHolder")} filter filterPlaceholder={t("documentCategorieIndex.indexElementPlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                    <div className="field col-5">
                        <label htmlFor="documentCategorie">{t("documentCategorieIndex.documentCategorie")}</label>
                        <Dropdown  id="documentCategorieDropdown"  value={item.documentCategorie} options={documentCategories} onChange={(e) => onDropdownChange(e, 'documentCategorie')}   placeholder={t("documentCategorieIndex.documentCategoriePlaceHolder")} filter filterPlaceholder={t("documentCategorieIndex.documentCategoriePlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                    <div className="field col-5">
                        <label htmlFor="documentCategorieIndexRule">{t("documentCategorieIndex.documentCategorieIndexRule")}</label>
                        <Dropdown  id="documentCategorieIndexRuleDropdown"  value={item.documentCategorieIndexRule} options={documentCategorieIndexRules} onChange={(e) => onDropdownChange(e, 'documentCategorieIndexRule')}   placeholder={t("documentCategorieIndex.documentCategorieIndexRulePlaceHolder")} filter filterPlaceholder={t("documentCategorieIndex.documentCategorieIndexRulePlaceHolderFilter")} optionLabel="libelle" showClear/>
                    </div>
                </div>
            </TabPanel>
        </TabView>
    </Dialog>
);
};
export default Create;
