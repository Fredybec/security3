import axios, {AxiosResponse} from "axios";
import {RoleDto} from "../dto/RoleDto.model";
import {ROLES_URL} from "../../../layout/AppConfig";

class RoleService{

    getList(): Promise<AxiosResponse<RoleDto[]>> {
        return axios.get(ROLES_URL);
    }

}

export default RoleService;
