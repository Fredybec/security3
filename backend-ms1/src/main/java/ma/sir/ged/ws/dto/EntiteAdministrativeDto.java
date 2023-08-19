package  ma.sir.ged.ws.dto;

import ma.sir.ged.zynerator.audit.Log;
import ma.sir.ged.zynerator.dto.AuditBaseDto;
import com.fasterxml.jackson.annotation.JsonInclude;



@JsonInclude(JsonInclude.Include.NON_NULL)
public class EntiteAdministrativeDto  extends AuditBaseDto {

    private String code  ;
    private String codeEntiteAdminParent  ;
    private String referenceGed  ;
    private String description  ;
    private String libelle  ;

    private UtilisateurDto utilisateur ;
    private EntiteAdministrativeTypeDto entiteAdministrativeType ;



    public EntiteAdministrativeDto(){
        super();
    }



    @Log
    public String getCode(){
        return this.code;
    }
    public void setCode(String code){
        this.code = code;
    }

    @Log
    public String getCodeEntiteAdminParent(){
        return this.codeEntiteAdminParent;
    }
    public void setCodeEntiteAdminParent(String codeEntiteAdminParent){
        this.codeEntiteAdminParent = codeEntiteAdminParent;
    }

    @Log
    public String getReferenceGed(){
        return this.referenceGed;
    }
    public void setReferenceGed(String referenceGed){
        this.referenceGed = referenceGed;
    }

    @Log
    public String getDescription(){
        return this.description;
    }
    public void setDescription(String description){
        this.description = description;
    }

    @Log
    public String getLibelle(){
        return this.libelle;
    }
    public void setLibelle(String libelle){
        this.libelle = libelle;
    }


    public UtilisateurDto getUtilisateur(){
        return this.utilisateur;
    }

    public void setUtilisateur(UtilisateurDto utilisateur){
        this.utilisateur = utilisateur;
    }
    public EntiteAdministrativeTypeDto getEntiteAdministrativeType(){
        return this.entiteAdministrativeType;
    }

    public void setEntiteAdministrativeType(EntiteAdministrativeTypeDto entiteAdministrativeType){
        this.entiteAdministrativeType = entiteAdministrativeType;
    }




}
