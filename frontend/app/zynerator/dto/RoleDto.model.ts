import {BaseDto} from "./BaseDto.model";

export class RoleDto extends BaseDto{

    authority: string;
    label: string;
    getClassName() {
        return "User";
    }
}