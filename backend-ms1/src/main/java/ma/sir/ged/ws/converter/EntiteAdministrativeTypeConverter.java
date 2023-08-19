package  ma.sir.ged.ws.converter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


import ma.sir.ged.zynerator.util.StringUtil;
import ma.sir.ged.zynerator.converter.AbstractConverter;
import ma.sir.ged.zynerator.util.DateUtil;
import ma.sir.ged.bean.history.EntiteAdministrativeTypeHistory;
import ma.sir.ged.bean.core.EntiteAdministrativeType;
import ma.sir.ged.ws.dto.EntiteAdministrativeTypeDto;

@Component
public class EntiteAdministrativeTypeConverter extends AbstractConverter<EntiteAdministrativeType, EntiteAdministrativeTypeDto, EntiteAdministrativeTypeHistory> {


    public  EntiteAdministrativeTypeConverter(){
        super(EntiteAdministrativeType.class, EntiteAdministrativeTypeDto.class, EntiteAdministrativeTypeHistory.class);
    }

    @Override
    public EntiteAdministrativeType toItem(EntiteAdministrativeTypeDto dto) {
        if (dto == null) {
            return null;
        } else {
        EntiteAdministrativeType item = new EntiteAdministrativeType();
            if(StringUtil.isNotEmpty(dto.getId()))
                item.setId(dto.getId());
            if(StringUtil.isNotEmpty(dto.getCode()))
                item.setCode(dto.getCode());
            if(StringUtil.isNotEmpty(dto.getLibelle()))
                item.setLibelle(dto.getLibelle());
            if(StringUtil.isNotEmpty(dto.getDescription()))
                item.setDescription(dto.getDescription());


        return item;
        }
    }

    @Override
    public EntiteAdministrativeTypeDto toDto(EntiteAdministrativeType item) {
        if (item == null) {
            return null;
        } else {
            EntiteAdministrativeTypeDto dto = new EntiteAdministrativeTypeDto();
            if(StringUtil.isNotEmpty(item.getId()))
                dto.setId(item.getId());
            if(StringUtil.isNotEmpty(item.getCode()))
                dto.setCode(item.getCode());
            if(StringUtil.isNotEmpty(item.getLibelle()))
                dto.setLibelle(item.getLibelle());
            if(StringUtil.isNotEmpty(item.getDescription()))
                dto.setDescription(item.getDescription());


        return dto;
        }
    }


    public void initObject(boolean value) {
    }


}
