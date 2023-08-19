package  ma.sir.ged.ws.converter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import ma.sir.ged.bean.core.Document;

import ma.sir.ged.zynerator.util.StringUtil;
import ma.sir.ged.zynerator.converter.AbstractConverter;
import ma.sir.ged.zynerator.util.DateUtil;
import ma.sir.ged.bean.history.DocumentIndexElementHistory;
import ma.sir.ged.bean.core.DocumentIndexElement;
import ma.sir.ged.ws.dto.DocumentIndexElementDto;

@Component
public class DocumentIndexElementConverter extends AbstractConverter<DocumentIndexElement, DocumentIndexElementDto, DocumentIndexElementHistory> {

    @Autowired
    private IndexElementConverter indexElementConverter ;
    @Autowired
    private DocumentConverter documentConverter ;
    private boolean indexElement;
    private boolean document;

    public  DocumentIndexElementConverter(){
        super(DocumentIndexElement.class, DocumentIndexElementDto.class, DocumentIndexElementHistory.class);
    }

    @Override
    public DocumentIndexElement toItem(DocumentIndexElementDto dto) {
        if (dto == null) {
            return null;
        } else {
        DocumentIndexElement item = new DocumentIndexElement();
            if(StringUtil.isNotEmpty(dto.getId()))
                item.setId(dto.getId());
            if(StringUtil.isNotEmpty(dto.getValue()))
                item.setValue(dto.getValue());
            if(StringUtil.isNotEmpty(dto.getDescription()))
                item.setDescription(dto.getDescription());
            if(this.indexElement && dto.getIndexElement()!=null &&  dto.getIndexElement().getId() != null)
                item.setIndexElement(indexElementConverter.toItem(dto.getIndexElement())) ;

            if(dto.getDocument() != null && dto.getDocument().getId() != null){
                item.setDocument(new Document());
                item.getDocument().setId(dto.getDocument().getId());
            }



        return item;
        }
    }

    @Override
    public DocumentIndexElementDto toDto(DocumentIndexElement item) {
        if (item == null) {
            return null;
        } else {
            DocumentIndexElementDto dto = new DocumentIndexElementDto();
            if(StringUtil.isNotEmpty(item.getId()))
                dto.setId(item.getId());
            if(StringUtil.isNotEmpty(item.getValue()))
                dto.setValue(item.getValue());
            if(StringUtil.isNotEmpty(item.getDescription()))
                dto.setDescription(item.getDescription());
        if(this.indexElement && item.getIndexElement()!=null) {
            dto.setIndexElement(indexElementConverter.toDto(item.getIndexElement())) ;
        }
        if(this.document && item.getDocument()!=null) {
            dto.setDocument(documentConverter.toDto(item.getDocument())) ;
        }


        return dto;
        }
    }


    public void initObject(boolean value) {
        this.indexElement = value;
        this.document = value;
    }


    public IndexElementConverter getIndexElementConverter(){
        return this.indexElementConverter;
    }
    public void setIndexElementConverter(IndexElementConverter indexElementConverter ){
        this.indexElementConverter = indexElementConverter;
    }
    public DocumentConverter getDocumentConverter(){
        return this.documentConverter;
    }
    public void setDocumentConverter(DocumentConverter documentConverter ){
        this.documentConverter = documentConverter;
    }
    public boolean  isIndexElement(){
        return this.indexElement;
    }
    public void  setIndexElement(boolean indexElement){
        this.indexElement = indexElement;
    }
    public boolean  isDocument(){
        return this.document;
    }
    public void  setDocument(boolean document){
        this.document = document;
    }
}
