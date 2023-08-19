package  ma.sir.ged.ws.converter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


import ma.sir.ged.zynerator.util.StringUtil;
import ma.sir.ged.zynerator.converter.AbstractConverter;
import ma.sir.ged.zynerator.util.DateUtil;
import ma.sir.ged.bean.history.EntiteAdministrativeHistory;
import ma.sir.ged.bean.core.EntiteAdministrative;
import ma.sir.ged.ws.dto.EntiteAdministrativeDto;

@Component
public class EntiteAdministrativeConverter extends AbstractConverter<EntiteAdministrative, EntiteAdministrativeDto, EntiteAdministrativeHistory> {

    @Autowired
    private EntiteAdministrativeTypeConverter entiteAdministrativeTypeConverter ;
    @Autowired
    private UtilisateurConverter utilisateurConverter ;
    private boolean utilisateur;
    private boolean entiteAdministrativeType;

    public  EntiteAdministrativeConverter(){
        super(EntiteAdministrative.class, EntiteAdministrativeDto.class, EntiteAdministrativeHistory.class);
    }

    @Override
    public EntiteAdministrative toItem(EntiteAdministrativeDto dto) {
        if (dto == null) {
            return null;
        } else {
        EntiteAdministrative item = new EntiteAdministrative();
            if(StringUtil.isNotEmpty(dto.getId()))
                item.setId(dto.getId());
            if(StringUtil.isNotEmpty(dto.getCode()))
                item.setCode(dto.getCode());
            if(StringUtil.isNotEmpty(dto.getCodeEntiteAdminParent()))
                item.setCodeEntiteAdminParent(dto.getCodeEntiteAdminParent());
            if(StringUtil.isNotEmpty(dto.getReferenceGed()))
                item.setReferenceGed(dto.getReferenceGed());
            if(StringUtil.isNotEmpty(dto.getDescription()))
                item.setDescription(dto.getDescription());
            if(StringUtil.isNotEmpty(dto.getLibelle()))
                item.setLibelle(dto.getLibelle());
            if(this.utilisateur && dto.getUtilisateur()!=null &&  dto.getUtilisateur().getId() != null)
                item.setUtilisateur(utilisateurConverter.toItem(dto.getUtilisateur())) ;

            if(this.entiteAdministrativeType && dto.getEntiteAdministrativeType()!=null &&  dto.getEntiteAdministrativeType().getId() != null)
                item.setEntiteAdministrativeType(entiteAdministrativeTypeConverter.toItem(dto.getEntiteAdministrativeType())) ;



        return item;
        }
    }

    @Override
    public EntiteAdministrativeDto toDto(EntiteAdministrative item) {
        if (item == null) {
            return null;
        } else {
            EntiteAdministrativeDto dto = new EntiteAdministrativeDto();
            if(StringUtil.isNotEmpty(item.getId()))
                dto.setId(item.getId());
            if(StringUtil.isNotEmpty(item.getCode()))
                dto.setCode(item.getCode());
            if(StringUtil.isNotEmpty(item.getCodeEntiteAdminParent()))
                dto.setCodeEntiteAdminParent(item.getCodeEntiteAdminParent());
            if(StringUtil.isNotEmpty(item.getReferenceGed()))
                dto.setReferenceGed(item.getReferenceGed());
            if(StringUtil.isNotEmpty(item.getDescription()))
                dto.setDescription(item.getDescription());
            if(StringUtil.isNotEmpty(item.getLibelle()))
                dto.setLibelle(item.getLibelle());
        if(this.utilisateur && item.getUtilisateur()!=null) {
            dto.setUtilisateur(utilisateurConverter.toDto(item.getUtilisateur())) ;
        }
        if(this.entiteAdministrativeType && item.getEntiteAdministrativeType()!=null) {
            dto.setEntiteAdministrativeType(entiteAdministrativeTypeConverter.toDto(item.getEntiteAdministrativeType())) ;
        }


        return dto;
        }
    }


    public void initObject(boolean value) {
        this.utilisateur = value;
        this.entiteAdministrativeType = value;
    }


    public EntiteAdministrativeTypeConverter getEntiteAdministrativeTypeConverter(){
        return this.entiteAdministrativeTypeConverter;
    }
    public void setEntiteAdministrativeTypeConverter(EntiteAdministrativeTypeConverter entiteAdministrativeTypeConverter ){
        this.entiteAdministrativeTypeConverter = entiteAdministrativeTypeConverter;
    }
    public UtilisateurConverter getUtilisateurConverter(){
        return this.utilisateurConverter;
    }
    public void setUtilisateurConverter(UtilisateurConverter utilisateurConverter ){
        this.utilisateurConverter = utilisateurConverter;
    }
    public boolean  isUtilisateur(){
        return this.utilisateur;
    }
    public void  setUtilisateur(boolean utilisateur){
        this.utilisateur = utilisateur;
    }
    public boolean  isEntiteAdministrativeType(){
        return this.entiteAdministrativeType;
    }
    public void  setEntiteAdministrativeType(boolean entiteAdministrativeType){
        this.entiteAdministrativeType = entiteAdministrativeType;
    }
}
