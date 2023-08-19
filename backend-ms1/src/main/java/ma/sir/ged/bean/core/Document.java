package ma.sir.ged.bean.core;

import java.util.Objects;
import java.util.List;

import java.time.LocalDateTime;


import java.util.Date;
import com.fasterxml.jackson.annotation.JsonFormat;



import com.fasterxml.jackson.annotation.JsonInclude;
import ma.sir.ged.zynerator.audit.AuditBusinessObject;
import jakarta.persistence.*;
import java.util.Objects;


import java.math.BigDecimal;


@Entity
@Table(name = "document")
@JsonInclude(JsonInclude.Include.NON_NULL)
@SequenceGenerator(name="document_seq",sequenceName="document_seq",allocationSize=1, initialValue = 1)
public class Document   extends AuditBusinessObject     {

    private Long id;

    @Column(length = 500)
    private String reference;
    @Lob
    @Column(columnDefinition="TEXT")
    private String referenceGed;
    private LocalDateTime uploadDate ;
    private Long annee ;
    private Long semstre ;
    private Long mois ;
    private Long jour ;
    @Column(columnDefinition = "boolean default false")
    private Boolean ocr = false;
    @Column(length = 500)
    private String content;
    private BigDecimal size = BigDecimal.ZERO;
    @Column(length = 500)
    private String description;
    @Column(columnDefinition = "boolean default false")
    private Boolean archive = false;
    @Column(columnDefinition = "boolean default false")
    private Boolean versionne = false;

    private DocumentType documentType ;
    
    private DocumentState documentState ;
    
    private DocumentCategorie documentCategorie ;
    
    private Utilisateur utilisateur ;
    
    private EntiteAdministrative entiteAdministrative ;
    
    private DocumentCategorieModel documentCategorieModel ;
    

    private List<DocumentIndexElement> documentIndexElements ;
    private List<DocumentPartageGroupe> documentPartageGroupes ;
    private List<DocumentPartageUtilisateur> documentPartageUtilisateurs ;
    private List<DocumentTag> documentTags ;

    public Document(){
        super();
    }

    public Document(Long id,String reference){
        this.id = id;
        this.reference = reference ;
    }




    @Id
    @Column(name = "id")
        @GeneratedValue(strategy = GenerationType.SEQUENCE,generator="document_seq")
    public Long getId(){
        return this.id;
    }
    public void setId(Long id){
        this.id = id;
    }
    public String getReference(){
        return this.reference;
    }
    public void setReference(String reference){
        this.reference = reference;
    }
    public String getReferenceGed(){
        return this.referenceGed;
    }
    public void setReferenceGed(String referenceGed){
        this.referenceGed = referenceGed;
    }
    public LocalDateTime getUploadDate(){
        return this.uploadDate;
    }
    public void setUploadDate(LocalDateTime uploadDate){
        this.uploadDate = uploadDate;
    }
    public Long getAnnee(){
        return this.annee;
    }
    public void setAnnee(Long annee){
        this.annee = annee;
    }
    public Long getSemstre(){
        return this.semstre;
    }
    public void setSemstre(Long semstre){
        this.semstre = semstre;
    }
    public Long getMois(){
        return this.mois;
    }
    public void setMois(Long mois){
        this.mois = mois;
    }
    public Long getJour(){
        return this.jour;
    }
    public void setJour(Long jour){
        this.jour = jour;
    }
    public Boolean  getOcr(){
        return this.ocr;
    }
    public void setOcr(Boolean ocr){
        this.ocr = ocr;
    }
    public String getContent(){
        return this.content;
    }
    public void setContent(String content){
        this.content = content;
    }
    public BigDecimal getSize(){
        return this.size;
    }
    public void setSize(BigDecimal size){
        this.size = size;
    }
    @ManyToOne(fetch = FetchType.LAZY)
    public DocumentType getDocumentType(){
        return this.documentType;
    }
    public void setDocumentType(DocumentType documentType){
        this.documentType = documentType;
    }
    @ManyToOne(fetch = FetchType.LAZY)
    public DocumentState getDocumentState(){
        return this.documentState;
    }
    public void setDocumentState(DocumentState documentState){
        this.documentState = documentState;
    }
    @ManyToOne(fetch = FetchType.LAZY)
    public DocumentCategorie getDocumentCategorie(){
        return this.documentCategorie;
    }
    public void setDocumentCategorie(DocumentCategorie documentCategorie){
        this.documentCategorie = documentCategorie;
    }
    @OneToMany(mappedBy = "document")
    public List<DocumentIndexElement> getDocumentIndexElements(){
        return this.documentIndexElements;
    }
    public void setDocumentIndexElements(List<DocumentIndexElement> documentIndexElements){
        this.documentIndexElements = documentIndexElements;
    }
    public String getDescription(){
        return this.description;
    }
    public void setDescription(String description){
        this.description = description;
    }
    @ManyToOne(fetch = FetchType.LAZY)
    public Utilisateur getUtilisateur(){
        return this.utilisateur;
    }
    public void setUtilisateur(Utilisateur utilisateur){
        this.utilisateur = utilisateur;
    }
    public Boolean  getArchive(){
        return this.archive;
    }
    public void setArchive(Boolean archive){
        this.archive = archive;
    }
    public Boolean  getVersionne(){
        return this.versionne;
    }
    public void setVersionne(Boolean versionne){
        this.versionne = versionne;
    }
    @ManyToOne(fetch = FetchType.LAZY)
    public EntiteAdministrative getEntiteAdministrative(){
        return this.entiteAdministrative;
    }
    public void setEntiteAdministrative(EntiteAdministrative entiteAdministrative){
        this.entiteAdministrative = entiteAdministrative;
    }
    @ManyToOne(fetch = FetchType.LAZY)
    public DocumentCategorieModel getDocumentCategorieModel(){
        return this.documentCategorieModel;
    }
    public void setDocumentCategorieModel(DocumentCategorieModel documentCategorieModel){
        this.documentCategorieModel = documentCategorieModel;
    }
    @OneToMany(mappedBy = "document")
    public List<DocumentPartageGroupe> getDocumentPartageGroupes(){
        return this.documentPartageGroupes;
    }
    public void setDocumentPartageGroupes(List<DocumentPartageGroupe> documentPartageGroupes){
        this.documentPartageGroupes = documentPartageGroupes;
    }
    @OneToMany(mappedBy = "document")
    public List<DocumentPartageUtilisateur> getDocumentPartageUtilisateurs(){
        return this.documentPartageUtilisateurs;
    }
    public void setDocumentPartageUtilisateurs(List<DocumentPartageUtilisateur> documentPartageUtilisateurs){
        this.documentPartageUtilisateurs = documentPartageUtilisateurs;
    }
    @OneToMany(mappedBy = "document")
    public List<DocumentTag> getDocumentTags(){
        return this.documentTags;
    }
    public void setDocumentTags(List<DocumentTag> documentTags){
        this.documentTags = documentTags;
    }

    @Transient
    public String getLabel() {
        label = reference;
        return label;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Document document = (Document) o;
        return id != null && id.equals(document.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

}

