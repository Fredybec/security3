package  ma.sir.ged.ws.dto;

import ma.sir.ged.zynerator.audit.Log;
import ma.sir.ged.zynerator.dto.AuditBaseDto;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Date;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import com.fasterxml.jackson.annotation.JsonFormat;
import java.math.BigDecimal;


@JsonInclude(JsonInclude.Include.NON_NULL)
public class DocumentDto  extends AuditBaseDto {

    private String reference  ;
    private String referenceGed  ;
    private String uploadDate ;
    private Long annee  ;
    private Long semstre  ;
    private Long mois  ;
    private Long jour  ;
    private Boolean ocr  ;
    private String content  ;
    private BigDecimal size  ;
    private String description  ;
    private Boolean archive  ;
    private Boolean versionne  ;

    private DocumentTypeDto documentType ;
    private DocumentStateDto documentState ;
    private DocumentCategorieDto documentCategorie ;
    private UtilisateurDto utilisateur ;
    private EntiteAdministrativeDto entiteAdministrative ;
    private DocumentCategorieModelDto documentCategorieModel ;

    private List<DocumentIndexElementDto> documentIndexElements ;
    private List<DocumentPartageGroupeDto> documentPartageGroupes ;
    private List<DocumentPartageUtilisateurDto> documentPartageUtilisateurs ;
    private List<DocumentTagDto> documentTags ;


    public DocumentDto(){
        super();
    }



    @Log
    public String getReference(){
        return this.reference;
    }
    public void setReference(String reference){
        this.reference = reference;
    }

    @Log
    public String getReferenceGed(){
        return this.referenceGed;
    }
    public void setReferenceGed(String referenceGed){
        this.referenceGed = referenceGed;
    }

    @Log
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd/MM/yyyy HH:mm")
    public String getUploadDate(){
        return this.uploadDate;
    }
    public void setUploadDate(String uploadDate){
        this.uploadDate = uploadDate;
    }

    @Log
    public Long getAnnee(){
        return this.annee;
    }
    public void setAnnee(Long annee){
        this.annee = annee;
    }

    @Log
    public Long getSemstre(){
        return this.semstre;
    }
    public void setSemstre(Long semstre){
        this.semstre = semstre;
    }

    @Log
    public Long getMois(){
        return this.mois;
    }
    public void setMois(Long mois){
        this.mois = mois;
    }

    @Log
    public Long getJour(){
        return this.jour;
    }
    public void setJour(Long jour){
        this.jour = jour;
    }

    @Log
    public Boolean getOcr(){
        return this.ocr;
    }
    public void setOcr(Boolean ocr){
        this.ocr = ocr;
    }

    @Log
    public String getContent(){
        return this.content;
    }
    public void setContent(String content){
        this.content = content;
    }

    @Log
    public BigDecimal getSize(){
        return this.size;
    }
    public void setSize(BigDecimal size){
        this.size = size;
    }

    @Log
    public String getDescription(){
        return this.description;
    }
    public void setDescription(String description){
        this.description = description;
    }

    @Log
    public Boolean getArchive(){
        return this.archive;
    }
    public void setArchive(Boolean archive){
        this.archive = archive;
    }

    @Log
    public Boolean getVersionne(){
        return this.versionne;
    }
    public void setVersionne(Boolean versionne){
        this.versionne = versionne;
    }


    public DocumentTypeDto getDocumentType(){
        return this.documentType;
    }

    public void setDocumentType(DocumentTypeDto documentType){
        this.documentType = documentType;
    }
    public DocumentStateDto getDocumentState(){
        return this.documentState;
    }

    public void setDocumentState(DocumentStateDto documentState){
        this.documentState = documentState;
    }
    public DocumentCategorieDto getDocumentCategorie(){
        return this.documentCategorie;
    }

    public void setDocumentCategorie(DocumentCategorieDto documentCategorie){
        this.documentCategorie = documentCategorie;
    }
    public UtilisateurDto getUtilisateur(){
        return this.utilisateur;
    }

    public void setUtilisateur(UtilisateurDto utilisateur){
        this.utilisateur = utilisateur;
    }
    public EntiteAdministrativeDto getEntiteAdministrative(){
        return this.entiteAdministrative;
    }

    public void setEntiteAdministrative(EntiteAdministrativeDto entiteAdministrative){
        this.entiteAdministrative = entiteAdministrative;
    }
    public DocumentCategorieModelDto getDocumentCategorieModel(){
        return this.documentCategorieModel;
    }

    public void setDocumentCategorieModel(DocumentCategorieModelDto documentCategorieModel){
        this.documentCategorieModel = documentCategorieModel;
    }



    public List<DocumentIndexElementDto> getDocumentIndexElements(){
        return this.documentIndexElements;
    }

    public void setDocumentIndexElements(List<DocumentIndexElementDto> documentIndexElements){
        this.documentIndexElements = documentIndexElements;
    }
    public List<DocumentPartageGroupeDto> getDocumentPartageGroupes(){
        return this.documentPartageGroupes;
    }

    public void setDocumentPartageGroupes(List<DocumentPartageGroupeDto> documentPartageGroupes){
        this.documentPartageGroupes = documentPartageGroupes;
    }
    public List<DocumentPartageUtilisateurDto> getDocumentPartageUtilisateurs(){
        return this.documentPartageUtilisateurs;
    }

    public void setDocumentPartageUtilisateurs(List<DocumentPartageUtilisateurDto> documentPartageUtilisateurs){
        this.documentPartageUtilisateurs = documentPartageUtilisateurs;
    }
    public List<DocumentTagDto> getDocumentTags(){
        return this.documentTags;
    }

    public void setDocumentTags(List<DocumentTagDto> documentTags){
        this.documentTags = documentTags;
    }

}
