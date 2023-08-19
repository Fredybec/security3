package ma.sir.ged.service.facade.open;

import ma.sir.ged.bean.core.NodeDto;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface MinIOService {

    int bucketExists(String bucket);

    int upload(MultipartFile file, String bucket);

    int saveBucket(String bucket);

    List<NodeDto> findAllDocumentsAsNode(String bucket);

    List<NodeDto> transformToNode(List<String> allDocuments);


    List<NodeDto> buildTree(List<String> paths);

    List<String> findAllDocuments(String bucket);

    byte[] downloadAllDocumentsAsZip(String bucket);

    String getUrlAccess(String bucket, String path);

    List<String> getObjectsInFolder(String bucketName, String folderPath);

    List<String> mergeLists(List<String> list1, List<String> list2);
}
