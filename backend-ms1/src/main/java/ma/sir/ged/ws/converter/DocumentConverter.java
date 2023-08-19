package  ma.sir.ged.ws.converter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import ma.sir.ged.zynerator.util.ListUtil;

import ma.sir.ged.bean.core.DocumentCategorie;

import ma.sir.ged.zynerator.util.StringUtil;
import ma.sir.ged.zynerator.converter.AbstractConverter;
import ma.sir.ged.zynerator.util.DateUtil;
import ma.sir.ged.bean.history.DocumentHistory;
import ma.sir.ged.bean.core.Document;
import ma.sir.ged.ws.dto.DocumentDto;

@Component
public class DocumentConverter extends AbstractConverter<Document, DocumentDto, DocumentHistory> {

    @Autowired
    private DocumentCategorieModelConverter documentCategorieModelConverter ;
    @Autowired
    private GroupeConverter groupeConverter ;
    @Autowired
    private DocumentCategorieConverter documentCategorieConverter ;
    @Autowired
    private IndexElementConverter indexElementConverter ;
    @Autowired
    private AccessShareConverter accessShareConverter ;
    @Autowired
    private DocumentStateConverter documentStateConverter ;
    @Autowired
    private DocumentTagConverter documentTagConverter ;
    @Autowired
    private UtilisateurConverter utilisateurConverter ;
    @Autowired
    private EntiteAdministrativeConverter entiteAdministrativeConverter ;
    @Autowired
    private DocumentPartageGroupeConverter documentPartageGroupeConverter ;
    @Autowired
    private TagConverter tagConverter ;
    @Autowired
    private DocumentPartageUtilisateurConverter documentPartageUtilisateurConverter ;
    @Autowired
    private DocumentIndexElementConverter documentIndexElementConverter ;
    @Autowired
    private DocumentTypeConverter documentTypeConverter ;
    private boolean documentType;
    private boolean documentState;
    private boolean documentCategorie;
    private boolean utilisateur;
    private boolean entiteAdministrative;
    private boolean documentCategorieModel;
    private boolean documentIndexElements;
    private boolean documentPartageGroupes;
    private boolean documentPartageUtilisateurs;
    private boolean documentTags;

    public  DocumentConverter(){
        super(Document.class, DocumentDto.class, DocumentHistory.class);
        init(true);
    }

    @Override
    public Document toItem(DocumentDto dto) {
        if (dto == null) {
            return null;
        } else {
        Document item = new Document();
            if(StringUtil.isNotEmpty(dto.getId()))
                item.setId(dto.getId());
            if(StringUtil.isNotEmpty(dto.getReference()))
                item.setReference(dto.getReference());
            if(StringUtil.isNotEmpty(dto.getReferenceGed()))
                item.setReferenceGed(dto.getReferenceGed());
            if(StringUtil.isNotEmpty(dto.getUploadDate()))
                item.setUploadDate(DateUtil.stringEnToDate(dto.getUploadDate()));
            if(StringUtil.isNotEmpty(dto.getAnnee()))
                item.setAnnee(dto.getAnnee());
            if(StringUtil.isNotEmpty(dto.getSemstre()))
                item.setSemstre(dto.getSemstre());
            if(StringUtil.isNotEmpty(dto.getMois()))
                item.setMois(dto.getMois());
            if(StringUtil.isNotEmpty(dto.getJour()))
                item.setJour(dto.getJour());
            if(dto.getOcr() != null)
                item.setOcr(dto.getOcr());
            if(StringUtil.isNotEmpty(dto.getContent()))
                item.setContent(dto.getContent());
            if(StringUtil.isNotEmpty(dto.getSize()))
                item.setSize(dto.getSize());
            if(StringUtil.isNotEmpty(dto.getDescription()))
                item.setDescription(dto.getDescription());
            if(dto.getArchive() != null)
                item.setArchive(dto.getArchive());
            if(dto.getVersionne() != null)
                item.setVersionne(dto.getVersionne());
            if(this.documentType && dto.getDocumentType()!=null &&  dto.getDocumentType().getId() != null)
                item.setDocumentType(documentTypeConverter.toItem(dto.getDocumentType())) ;

            if(this.documentState && dto.getDocumentState()!=null &&  dto.getDocumentState().getId() != null)
                item.setDocumentState(documentStateConverter.toItem(dto.getDocumentState())) ;

            if(dto.getDocumentCategorie() != null && dto.getDocumentCategorie().getId() != null){
                item.setDocumentCategorie(new DocumentCategorie());
                item.getDocumentCategorie().setId(dto.getDocumentCategorie().getId());
            }

            if(this.utilisateur && dto.getUtilisateur()!=null &&  dto.getUtilisateur().getId() != null)
                item.setUtilisateur(utilisateurConverter.toItem(dto.getUtilisateur())) ;

            if(this.entiteAdministrative && dto.getEntiteAdministrative()!=null &&  dto.getEntiteAdministrative().getId() != null)
                item.setEntiteAdministrative(entiteAdministrativeConverter.toItem(dto.getEntiteAdministrative())) ;

            if(this.documentCategorieModel && dto.getDocumentCategorieModel()!=null &&  dto.getDocumentCategorieModel().getId() != null)
                item.setDocumentCategorieModel(documentCategorieModelConverter.toItem(dto.getDocumentCategorieModel())) ;


            if(this.documentIndexElements && ListUtil.isNotEmpty(dto.getDocumentIndexElements()))
                item.setDocumentIndexElements(documentIndexElementConverter.toItem(dto.getDocumentIndexElements()));
            if(this.documentPartageGroupes && ListUtil.isNotEmpty(dto.getDocumentPartageGroupes()))
                item.setDocumentPartageGroupes(documentPartageGroupeConverter.toItem(dto.getDocumentPartageGroupes()));
            if(this.documentPartageUtilisateurs && ListUtil.isNotEmpty(dto.getDocumentPartageUtilisateurs()))
                item.setDocumentPartageUtilisateurs(documentPartageUtilisateurConverter.toItem(dto.getDocumentPartageUtilisateurs()));
            if(this.documentTags && ListUtil.isNotEmpty(dto.getDocumentTags()))
                item.setDocumentTags(documentTagConverter.toItem(dto.getDocumentTags()));

        return item;
        }
    }

    @Override
    public DocumentDto toDto(Document item) {
        if (item == null) {
            return null;
        } else {
            DocumentDto dto = new DocumentDto();
            if(StringUtil.isNotEmpty(item.getId()))
                dto.setId(item.getId());
            if(StringUtil.isNotEmpty(item.getReference()))
                dto.setReference(item.getReference());
            if(StringUtil.isNotEmpty(item.getReferenceGed()))
                dto.setReferenceGed(item.getReferenceGed());
            if(item.getUploadDate()!=null)
                dto.setUploadDate(DateUtil.dateTimeToString(item.getUploadDate()));
            if(StringUtil.isNotEmpty(item.getAnnee()))
                dto.setAnnee(item.getAnnee());
            if(StringUtil.isNotEmpty(item.getSemstre()))
                dto.setSemstre(item.getSemstre());
            if(StringUtil.isNotEmpty(item.getMois()))
                dto.setMois(item.getMois());
            if(StringUtil.isNotEmpty(item.getJour()))
                dto.setJour(item.getJour());
                dto.setOcr(item.getOcr());
            if(StringUtil.isNotEmpty(item.getContent()))
                dto.setContent(item.getContent());
            if(StringUtil.isNotEmpty(item.getSize()))
                dto.setSize(item.getSize());
            if(StringUtil.isNotEmpty(item.getDescription()))
                dto.setDescription(item.getDescription());
                dto.setArchive(item.getArchive());
                dto.setVersionne(item.getVersionne());
        if(this.documentType && item.getDocumentType()!=null) {
            dto.setDocumentType(documentTypeConverter.toDto(item.getDocumentType())) ;
        }
        if(this.documentState && item.getDocumentState()!=null) {
            dto.setDocumentState(documentStateConverter.toDto(item.getDocumentState())) ;
        }
        if(this.documentCategorie && item.getDocumentCategorie()!=null) {
            dto.setDocumentCategorie(documentCategorieConverter.toDto(item.getDocumentCategorie())) ;
        }
        if(this.utilisateur && item.getUtilisateur()!=null) {
            dto.setUtilisateur(utilisateurConverter.toDto(item.getUtilisateur())) ;
        }
        if(this.entiteAdministrative && item.getEntiteAdministrative()!=null) {
            dto.setEntiteAdministrative(entiteAdministrativeConverter.toDto(item.getEntiteAdministrative())) ;
        }
        if(this.documentCategorieModel && item.getDocumentCategorieModel()!=null) {
            dto.setDocumentCategorieModel(documentCategorieModelConverter.toDto(item.getDocumentCategorieModel())) ;
        }
        if(this.documentIndexElements && ListUtil.isNotEmpty(item.getDocumentIndexElements())){
            documentIndexElementConverter.init(true);
            documentIndexElementConverter.setDocument(false);
            dto.setDocumentIndexElements(documentIndexElementConverter.toDto(item.getDocumentIndexElements()));
            documentIndexElementConverter.setDocument(true);

        }
        if(this.documentPartageGroupes && ListUtil.isNotEmpty(item.getDocumentPartageGroupes())){
            documentPartageGroupeConverter.init(true);
            documentPartageGroupeConverter.setDocument(false);
            dto.setDocumentPartageGroupes(documentPartageGroupeConverter.toDto(item.getDocumentPartageGroupes()));
            documentPartageGroupeConverter.setDocument(true);

        }
        if(this.documentPartageUtilisateurs && ListUtil.isNotEmpty(item.getDocumentPartageUtilisateurs())){
            documentPartageUtilisateurConverter.init(true);
            documentPartageUtilisateurConverter.setDocument(false);
            dto.setDocumentPartageUtilisateurs(documentPartageUtilisateurConverter.toDto(item.getDocumentPartageUtilisateurs()));
            documentPartageUtilisateurConverter.setDocument(true);

        }
        if(this.documentTags && ListUtil.isNotEmpty(item.getDocumentTags())){
            documentTagConverter.init(true);
            documentTagConverter.setDocument(false);
            dto.setDocumentTags(documentTagConverter.toDto(item.getDocumentTags()));
            documentTagConverter.setDocument(true);

        }


        return dto;
        }
    }

    public void initList(boolean value) {
        this.documentIndexElements = value;
        this.documentPartageGroupes = value;
        this.documentPartageUtilisateurs = value;
        this.documentTags = value;
    }

    public void initObject(boolean value) {
        this.documentType = value;
        this.documentState = value;
        this.documentCategorie = value;
        this.utilisateur = value;
        this.entiteAdministrative = value;
        this.documentCategorieModel = value;
    }


    public DocumentCategorieModelConverter getDocumentCategorieModelConverter(){
        return this.documentCategorieModelConverter;
    }
    public void setDocumentCategorieModelConverter(DocumentCategorieModelConverter documentCategorieModelConverter ){
        this.documentCategorieModelConverter = documentCategorieModelConverter;
    }
    public GroupeConverter getGroupeConverter(){
        return this.groupeConverter;
    }
    public void setGroupeConverter(GroupeConverter groupeConverter ){
        this.groupeConverter = groupeConverter;
    }
    public DocumentCategorieConverter getDocumentCategorieConverter(){
        return this.documentCategorieConverter;
    }
    public void setDocumentCategorieConverter(DocumentCategorieConverter documentCategorieConverter ){
        this.documentCategorieConverter = documentCategorieConverter;
    }
    public IndexElementConverter getIndexElementConverter(){
        return this.indexElementConverter;
    }
    public void setIndexElementConverter(IndexElementConverter indexElementConverter ){
        this.indexElementConverter = indexElementConverter;
    }
    public AccessShareConverter getAccessShareConverter(){
        return this.accessShareConverter;
    }
    public void setAccessShareConverter(AccessShareConverter accessShareConverter ){
        this.accessShareConverter = accessShareConverter;
    }
    public DocumentStateConverter getDocumentStateConverter(){
        return this.documentStateConverter;
    }
    public void setDocumentStateConverter(DocumentStateConverter documentStateConverter ){
        this.documentStateConverter = documentStateConverter;
    }
    public DocumentTagConverter getDocumentTagConverter(){
        return this.documentTagConverter;
    }
    public void setDocumentTagConverter(DocumentTagConverter documentTagConverter ){
        this.documentTagConverter = documentTagConverter;
    }
    public UtilisateurConverter getUtilisateurConverter(){
        return this.utilisateurConverter;
    }
    public void setUtilisateurConverter(UtilisateurConverter utilisateurConverter ){
        this.utilisateurConverter = utilisateurConverter;
    }
    public EntiteAdministrativeConverter getEntiteAdministrativeConverter(){
        return this.entiteAdministrativeConverter;
    }
    public void setEntiteAdministrativeConverter(EntiteAdministrativeConverter entiteAdministrativeConverter ){
        this.entiteAdministrativeConverter = entiteAdministrativeConverter;
    }
    public DocumentPartageGroupeConverter getDocumentPartageGroupeConverter(){
        return this.documentPartageGroupeConverter;
    }
    public void setDocumentPartageGroupeConverter(DocumentPartageGroupeConverter documentPartageGroupeConverter ){
        this.documentPartageGroupeConverter = documentPartageGroupeConverter;
    }
    public TagConverter getTagConverter(){
        return this.tagConverter;
    }
    public void setTagConverter(TagConverter tagConverter ){
        this.tagConverter = tagConverter;
    }
    public DocumentPartageUtilisateurConverter getDocumentPartageUtilisateurConverter(){
        return this.documentPartageUtilisateurConverter;
    }
    public void setDocumentPartageUtilisateurConverter(DocumentPartageUtilisateurConverter documentPartageUtilisateurConverter ){
        this.documentPartageUtilisateurConverter = documentPartageUtilisateurConverter;
    }
    public DocumentIndexElementConverter getDocumentIndexElementConverter(){
        return this.documentIndexElementConverter;
    }
    public void setDocumentIndexElementConverter(DocumentIndexElementConverter documentIndexElementConverter ){
        this.documentIndexElementConverter = documentIndexElementConverter;
    }
    public DocumentTypeConverter getDocumentTypeConverter(){
        return this.documentTypeConverter;
    }
    public void setDocumentTypeConverter(DocumentTypeConverter documentTypeConverter ){
        this.documentTypeConverter = documentTypeConverter;
    }
    public boolean  isDocumentType(){
        return this.documentType;
    }
    public void  setDocumentType(boolean documentType){
        this.documentType = documentType;
    }
    public boolean  isDocumentState(){
        return this.documentState;
    }
    public void  setDocumentState(boolean documentState){
        this.documentState = documentState;
    }
    public boolean  isDocumentCategorie(){
        return this.documentCategorie;
    }
    public void  setDocumentCategorie(boolean documentCategorie){
        this.documentCategorie = documentCategorie;
    }
    public boolean  isUtilisateur(){
        return this.utilisateur;
    }
    public void  setUtilisateur(boolean utilisateur){
        this.utilisateur = utilisateur;
    }
    public boolean  isEntiteAdministrative(){
        return this.entiteAdministrative;
    }
    public void  setEntiteAdministrative(boolean entiteAdministrative){
        this.entiteAdministrative = entiteAdministrative;
    }
    public boolean  isDocumentCategorieModel(){
        return this.documentCategorieModel;
    }
    public void  setDocumentCategorieModel(boolean documentCategorieModel){
        this.documentCategorieModel = documentCategorieModel;
    }
    public boolean  isDocumentIndexElements(){
        return this.documentIndexElements ;
    }
    public void  setDocumentIndexElements(boolean documentIndexElements ){
        this.documentIndexElements  = documentIndexElements ;
    }
    public boolean  isDocumentPartageGroupes(){
        return this.documentPartageGroupes ;
    }
    public void  setDocumentPartageGroupes(boolean documentPartageGroupes ){
        this.documentPartageGroupes  = documentPartageGroupes ;
    }
    public boolean  isDocumentPartageUtilisateurs(){
        return this.documentPartageUtilisateurs ;
    }
    public void  setDocumentPartageUtilisateurs(boolean documentPartageUtilisateurs ){
        this.documentPartageUtilisateurs  = documentPartageUtilisateurs ;
    }
    public boolean  isDocumentTags(){
        return this.documentTags ;
    }
    public void  setDocumentTags(boolean documentTags ){
        this.documentTags  = documentTags ;
    }
}
