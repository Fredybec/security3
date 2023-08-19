package ma.sir.ged.ws.facade.open;

import ma.sir.ged.bean.core.NodeDto;
import ma.sir.ged.service.facade.open.MinIOService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/open/minio")
public class MinioWs {
    @GetMapping("/test")
    public List<NodeDto> mergeLists() {
        List<String> list1 = minIOService.findAllDocuments("ged");
        List<String> list2 = minIOService.getObjectsInFolder("ged", "doc1");
        List<NodeDto> list3 = minIOService.buildTree( minIOService.mergeLists(list1, list2));
        return list3;
    }

    @Autowired
    private MinIOService minIOService;


    //--- Check if bucket exists or not ---
    //curl "http://localhost:8036/minio/bucket/my-bucket"
    @GetMapping("/bucket/{name}")
    public int bucketExists(@PathVariable String name) {
        return minIOService.bucketExists(name);
    }

    //--- Upload a file to the bucket ---
    //curl -X POST -F "file=@./file01.pdf" http://localhost:8036/minio/upload/file/my-bucket
    @PostMapping("/upload/file/{bucket}")
    public int upload(@RequestParam("file") MultipartFile file, @PathVariable String bucket) {
        return minIOService.upload(file, bucket);
    }

    //--- Create a new bucket ---
    //curl -X POST -F "bucketName=my-new-bucket" http://localhost:8036/minio/bucket
    @PostMapping("/bucket")
    public int saveBucket(@RequestParam("bucketName") String bucket) {
        return minIOService.saveBucket(bucket);
    }

    //--- List all files of a bucket ---
    //curl -X GET http://localhost:8036/minio/findAll/bucket/my-bucket
    @GetMapping("/findAll/bucket/{bucket}")
    public List<String> findAllDocuments(@PathVariable String bucket) {
        return minIOService.findAllDocuments(bucket);

    }

    //--- List all files of a bucket ---
    //curl -X GET http://localhost:8036/minio/findAll/bucket/my-bucket
    @GetMapping("/objectsInFolder")
    public List<String> getObjectsInFolder(
            @RequestParam String bucketName,
            @RequestParam String folderPath) {
        return minIOService.getObjectsInFolder(bucketName, folderPath);
    }

    //--- List all files of a bucket ---
    //curl -X GET http://localhost:8036/minio/findAllAsNode/bucket/my-bucket
    @GetMapping("/findAllAsNode/bucket/{bucket}")
    public List<NodeDto> findAllDocumentsAsNode(@PathVariable String bucket) {
        return minIOService.findAllDocumentsAsNode(bucket);

    }

    //--- Download all files from a bucket ---
    //curl -o D:/GED/all_documents.zip http://localhost:8036/minio/downloadAll/bucket/my-bucket
    @GetMapping("/downloadAll/bucket/{bucket}")
    public byte[] downloadAllDocumentsAsZip(@PathVariable String bucket) {
        return minIOService.downloadAllDocumentsAsZip(bucket);
    }

    //--- share a document from a bucket ---
    //GET:: http://localhost:8037/minio/bucket/url/ged/MicrosoftTeams-image (4).png
    @GetMapping("/bucket/url/{bucket}/{path}")
    public String getUrlAccess(@PathVariable String bucket, @PathVariable String path) {
        return minIOService.getUrlAccess(bucket, "ged/MicrosoftTeams-image (4).png");
    }

}