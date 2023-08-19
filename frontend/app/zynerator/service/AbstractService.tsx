import axios, {AxiosResponse} from "axios";
import {PaginatedList} from "../dto/PaginatedList.model";
import {BaseDto} from "../dto/BaseDto.model";
import {BaseCriteria} from "../criteria/BaseCriteria.model";
import {UtilisateurDto} from "../../controller/model/Utilisateur.model";

class AbstractService<T extends BaseDto, C extends BaseCriteria> {
    private _url: string




    constructor(private baseUrl: string, private beanName: string) {
        this._url = baseUrl + beanName;
    }


    getList(): Promise<AxiosResponse<T[]>> {
        return axios.get(this._url);
    }

    save(item: T): Promise<AxiosResponse<T>> {
        return axios.post(this._url, item);
    }

    update(item: T): Promise<AxiosResponse<T>> {
        return axios.put(this._url, item);
    }

    delete(id: number): Promise<AxiosResponse<T>> {
        return axios.delete(this._url + 'id/' + id);
    }

    deleteList(items: T[]): Promise<AxiosResponse<string>> {
        return axios.post(this._url + 'multiple', items);
    }

    findPaginatedByCriteria(criteria: C): Promise<AxiosResponse<PaginatedList<T>>> {
        return axios.post<PaginatedList<T>>(this._url + 'find-paginated-by-criteria', criteria);
    }

    handleDownload() {
        // Construct the download URL
        const objectName="compta";
        const fileName= "66.png"
        //const downloadUrl = `http://localhost:8036/api/open/minio/download/${objectName}/${fileName}`;
        const downloadUrl = `http://localhost:8036/api/open/minio/download/${objectName}`;

        // Create an anchor element and initiate the download
        const anchor = document.createElement('a');
        anchor.href = downloadUrl;
        anchor.download = objectName;
        anchor.target = '_blank'; // Open in new tab to trigger download
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
    };

    //const onUpload = (event:any) => {


    changePassword(username: string , password: string): Promise<AxiosResponse<any>> {
        let  utilisateur = new UtilisateurDto();
        utilisateur.password = password;
        utilisateur.username = username;
        return axios.put('http://localhost:8036/api/admin/utilisateur/changePassword',utilisateur);
    }

}

export default AbstractService;
