package ma.sir.ged.service.impl.open;

import io.minio.*;
import io.minio.messages.Item;
import ma.sir.ged.bean.core.NodeDto;
import ma.sir.ged.service.facade.open.MinIOService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import io.minio.http.Method;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
public class MinIOServiceImpl implements MinIOService {

    @Override
    public int bucketExists(String name) {
        try {
            boolean bucketExists = minioClient.bucketExists(BucketExistsArgs.builder().bucket(name).build());
            return bucketExists ? 1 : 0;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    @Override
    public int upload(MultipartFile file, String bucket) {

        if (bucketExists(bucket) != 1) {
            return 0;
        } else {
            try {
                minioClient.putObject(
                        PutObjectArgs.builder()
                                .bucket(bucket)
                                .object(file.getOriginalFilename())
                                .stream(file.getInputStream(), file.getSize(), -1)
                                .contentType(file.getContentType())
                                .build()
                );
                return 1;
            } catch (Exception e) {
                e.printStackTrace();
                return -1;
            }
        }
    }

    @Override
    public int saveBucket(String bucket) {
        if (bucketExists(bucket) == 1) return 0;
        else {
            try {
                minioClient.makeBucket(
                        MakeBucketArgs.builder()
                                .bucket(bucket)
                                .build()
                );
                return 1;
            } catch (Exception e) {
                e.printStackTrace();
                return 0;
            }
        }
    }


    @Override
    public List<NodeDto> findAllDocumentsAsNode(String bucket) {
        List<String> allDocuments = findAllDocuments(bucket);
        return transformToNode(allDocuments);
    }
//////////////////////////////////////////////
    @Override
    public List<NodeDto> transformToNode(List<String> allDocuments) {
        List<NodeDto> res = new ArrayList<>();
        Map<String, NodeDto> pathToNodeMap = new HashMap<>();

        for (String element : allDocuments) {
            NodeDto nodeDto = new NodeDto();
            nodeDto.setKey(element);
            nodeDto.setData(element);
            nodeDto.setLabel(getLabelFromPath(element));
            nodeDto.setIcon(isFile(element) ? "pi pi-fw pi-file" : "pi pi-fw pi-folder");

            pathToNodeMap.put(element, nodeDto);
            String parentPath = getParentPath(element);
            if (!parentPath.isEmpty()) {
                NodeDto parentNode = pathToNodeMap.get(parentPath);
                if (parentNode != null) {
                    if (parentNode.getChildren() == null) {
                        parentNode.setChildren(new ArrayList<>());
                    }
                    parentNode.getChildren().add(nodeDto);
                }
            } else {
                res.add(nodeDto);
            }
        }

        // Find elements with children and add them to the result list
        for (NodeDto node : pathToNodeMap.values()) {
            if (node.getChildren() != null && !node.getChildren().isEmpty()) {
                res.add(node);
            }
        }

        return res;
    }

    private String getParentPath(String path) {
        int lastSlashIndex = path.lastIndexOf("/");
        return lastSlashIndex >= 0 ? path.substring(0, lastSlashIndex) : "";
    }

    private String getLabelFromPath(String path) {
        int lastSlashIndex = path.lastIndexOf("/");
        return lastSlashIndex >= 0 ? path.substring(lastSlashIndex + 1) : path;
    }

    private boolean isFile(String path) {
        return path.contains(".");
    }

    @Override
    public List<NodeDto> buildTree(List<String> paths) {
        Map<String, NodeDto> nodeMap = new HashMap<>();
        List<NodeDto> rootNodes = new ArrayList<>();

        for (String path : paths) {
            String[] parts = path.split("/");
            NodeDto currentNode = null;
            NodeDto parentNode = null;

            for (String part : parts) {
                String key = (currentNode != null) ? currentNode.getKey() + "/" + part : part;

                if (!nodeMap.containsKey(key)) {
                    currentNode = new NodeDto();
                    currentNode.setKey(key);
                    currentNode.setLabel(part);
                    currentNode.setIcon(isFile(part) ? "pi pi-fw pi-file" : "pi pi-fw pi-folder");
                    nodeMap.put(key, currentNode);

                    if (parentNode != null) {
                        parentNode.getChildren().add(currentNode);
                    }

                    if (currentNode.getKey().equals(part)) {
                        rootNodes.add(currentNode);
                    }
                } else {
                    currentNode = nodeMap.get(key);
                }

                parentNode = currentNode;
            }
        }

        return rootNodes;
    }

    ////////////////////////////////

    @Override
    public List<String> findAllDocuments(String bucket) {
        List<String> documents = new ArrayList<>();
        List<String> res = new ArrayList<>();
        List<String> topLevelDirs = new ArrayList<>();
        if (bucketExists(bucket) != 1) return null;
        else {
            try {
                Iterable<Result<Item>> results = minioClient.listObjects(
                        ListObjectsArgs.builder().bucket(bucket).build()
                );

                for (Result<Item> result : results) {
                    Item item = result.get();
                    String objectName = item.objectName();
                    String[] parts = objectName.split("/"); // Split object name by '/'

                    // Check if the object is at the top level (no '/' in the name)
                    if (parts.length == 1) {
                        documents.add(objectName);
                    } else {
                        topLevelDirs.add(parts[0]);
                    }
                }

                // Remove top-level directories from the list
                // documents.removeAll(topLevelDirs);

                res.addAll(documents);
                res.addAll(topLevelDirs);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return res;
        }
    }

    @Override
    public byte[] downloadAllDocumentsAsZip(String bucket) {
        if (bucketExists(bucket) != 1) return null;
        else {
            try {
                List<String> documentNames = findAllDocuments(bucket);

                // Create a byte array output stream to hold the zip data
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ZipOutputStream zipOut = new ZipOutputStream(baos);

                // Buffer for reading data
                byte[] buffer = new byte[8192];

                // Loop through each document and add it to the zip
                for (String documentName : documentNames) {
                    // Get the document object from MinIO
                    GetObjectResponse response = minioClient.getObject(
                            GetObjectArgs.builder()
                                    .bucket(bucket)
                                    .object(documentName)
                                    .build()
                    );

                    // Get the input stream containing the document data
                    InputStream documentStream = response;

                    // Create a new entry in the zip for the document
                    ZipEntry zipEntry = new ZipEntry(documentName);
                    zipOut.putNextEntry(zipEntry);

                    // Write the document data to the zip
                    int bytesRead;
                    while ((bytesRead = documentStream.read(buffer)) != -1) {
                        zipOut.write(buffer, 0, bytesRead);
                    }

                    // Close the entry for the document
                    zipOut.closeEntry();

                    // Close the input stream for the current document
                    documentStream.close();
                }

                // Close the zip output stream
                zipOut.close();

                // Return the zip data as a byte array
                return baos.toByteArray();

            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    @Override
    public String getUrlAccess(String bucket, String path) {
        String[] splitPath = path.split("/");
        String fileName = splitPath[splitPath.length - 1];
        String presignedUrl = "";
        try {
            presignedUrl = minioClient.getPresignedObjectUrl(
                    GetPresignedObjectUrlArgs.builder()
                            .method(Method.GET)
                            .bucket("ged")
                            .object(fileName)
                            .expiry(60 * 60 * 24)
                            .build());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return presignedUrl;
    }

    @Override
    public List<String> getObjectsInFolder(String bucketName, String folderPath) {
        List<String> objectNames = new ArrayList<>();

        try {
//            Iterable<Result<Item>> results = minioClient.listObjects(
//                    ListObjectsArgs.builder()
//                            .bucket(bucketName)
//                            .prefix(folderPath) // Set the folder path as prefix
//                            .build()
//            );

            Iterable<Result<Item>> results = minioClient.listObjects(
                    ListObjectsArgs.builder()
                            .bucket(bucketName)
                            .prefix(folderPath + "/") // Add a trailing slash for the folder path
                            .delimiter("/") // Set the delimiter to "/"
                            .build()
            );
            for (Result<Item> result : results) {
                Item item = result.get();
                // Remove the folder path from the object name
//                String objectName = item.objectName().substring((folderPath + "/").length());
                String objectName = item.objectName();
                objectNames.add(objectName);
            }
        } catch (Exception e) {
            e.printStackTrace();
            // Handle other exceptions
        }

        return objectNames;
    }

    @Override
    public List<String> mergeLists(List<String> list1, List<String> list2) {
        Set<String> fullPaths = new HashSet<>(list2);
        List<String> mergedResult = new ArrayList<>();

        // Add the full paths from list2 to the result list
        for (String fullPath : list2) {
            mergedResult.add(fullPath);
        }

        // Add the remaining partial paths from list1 to the result
        for (String partialPath : list1) {
            if (!fullPaths.contains(partialPath + "/")) {
                mergedResult.add(partialPath);
            }
        }

        return mergedResult;
    }

    @Autowired
    private MinioClient minioClient;
}