package  ma.sir.ged.ws.facade.agent;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import ma.sir.ged.bean.core.IndexElement;
import ma.sir.ged.bean.history.IndexElementHistory;
import ma.sir.ged.dao.criteria.core.IndexElementCriteria;
import ma.sir.ged.dao.criteria.history.IndexElementHistoryCriteria;
import ma.sir.ged.service.facade.agent.IndexElementAgentService;
import ma.sir.ged.ws.converter.IndexElementConverter;
import ma.sir.ged.ws.dto.IndexElementDto;
import ma.sir.ged.zynerator.controller.AbstractController;
import ma.sir.ged.zynerator.dto.AuditEntityDto;
import ma.sir.ged.zynerator.util.PaginatedList;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import ma.sir.ged.zynerator.process.Result;


import org.springframework.web.multipart.MultipartFile;
import ma.sir.ged.zynerator.dto.FileTempDto;

@RestController
@RequestMapping("/api/agent/indexElement/")
public class IndexElementRestAgent  extends AbstractController<IndexElement, IndexElementDto, IndexElementHistory, IndexElementCriteria, IndexElementHistoryCriteria, IndexElementAgentService, IndexElementConverter> {



    @Operation(summary = "upload one indexElement")
    @RequestMapping(value = "upload", method = RequestMethod.POST, consumes = "multipart/form-data")
    public ResponseEntity<FileTempDto> uploadFileAndGetChecksum(@RequestBody MultipartFile file) throws Exception {
        return super.uploadFileAndGetChecksum(file);
    }
    @Operation(summary = "upload multiple indexElements")
    @RequestMapping(value = "upload-multiple", method = RequestMethod.POST, consumes = "multipart/form-data")
    public ResponseEntity<List<FileTempDto>> uploadMultipleFileAndGetChecksum(@RequestBody MultipartFile[] files) throws Exception {
        return super.uploadMultipleFileAndGetChecksum(files);
    }

    @Operation(summary = "Finds a list of all indexElements")
    @GetMapping("")
    public ResponseEntity<List<IndexElementDto>> findAll() throws Exception {
        return super.findAll();
    }

    @Operation(summary = "Finds an optimized list of all indexElements")
    @GetMapping("optimized")
    public ResponseEntity<List<IndexElementDto>> findAllOptimized() throws Exception {
        return super.findAllOptimized();
    }

    @Operation(summary = "Finds a indexElement by id")
    @GetMapping("id/{id}")
    public ResponseEntity<IndexElementDto> findById(@PathVariable Long id, String[] includes, String[] excludes) throws Exception {
        return super.findById(id, includes, excludes);
    }
    @Operation(summary = "Saves the specified  indexElement")
    @PostMapping("")
    public ResponseEntity<IndexElementDto> save(@RequestBody IndexElementDto dto) throws Exception {
        return super.save(dto);
    }

    @Operation(summary = "Updates the specified  indexElement")
    @PutMapping("")
    public ResponseEntity<IndexElementDto> update(@RequestBody IndexElementDto dto) throws Exception {
        return super.update(dto);
    }

    @Operation(summary = "Delete list of indexElement")
    @PostMapping("multiple")
    public ResponseEntity<List<IndexElementDto>> delete(@RequestBody List<IndexElementDto> listToDelete) throws Exception {
        return super.delete(listToDelete);
    }
    @Operation(summary = "Delete the specified indexElement")
    @DeleteMapping("")
    public ResponseEntity<IndexElementDto> delete(@RequestBody IndexElementDto dto) throws Exception {
            return super.delete(dto);
    }

    @Operation(summary = "Delete the specified indexElement")
    @DeleteMapping("id/{id}")
    public ResponseEntity<Long> deleteById(@PathVariable Long id) throws Exception {
        return super.deleteById(id);
    }
    @Operation(summary = "Delete multiple indexElements by ids")
    @DeleteMapping("multiple/id")
    public ResponseEntity<List<Long>> deleteByIdIn(@RequestBody List<Long> ids) throws Exception {
            return super.deleteByIdIn(ids);
     }


    @Operation(summary = "Finds indexElements by criteria")
    @PostMapping("find-by-criteria")
    public ResponseEntity<List<IndexElementDto>> findByCriteria(@RequestBody IndexElementCriteria criteria) throws Exception {
        return super.findByCriteria(criteria);
    }

    @Operation(summary = "Finds paginated indexElements by criteria")
    @PostMapping("find-paginated-by-criteria")
    public ResponseEntity<PaginatedList> findPaginatedByCriteria(@RequestBody IndexElementCriteria criteria) throws Exception {
        return super.findPaginatedByCriteria(criteria);
    }

    @Operation(summary = "Exports indexElements by criteria")
    @PostMapping("export")
    public ResponseEntity<InputStreamResource> export(@RequestBody IndexElementCriteria criteria) throws Exception {
        return super.export(criteria);
    }

    @Operation(summary = "Gets indexElement data size by criteria")
    @PostMapping("data-size-by-criteria")
    public ResponseEntity<Integer> getDataSize(@RequestBody IndexElementCriteria criteria) throws Exception {
        return super.getDataSize(criteria);
    }

    @Operation(summary = "Gets indexElement history by id")
    @GetMapping("history/id/{id}")
    public ResponseEntity<AuditEntityDto> findHistoryById(@PathVariable("id") Long id) throws Exception {
        return super.findHistoryById(id);
    }

    @Operation(summary = "Gets indexElement paginated history by criteria")
    @PostMapping("history-paginated-by-criteria")
    public ResponseEntity<PaginatedList> findHistoryPaginatedByCriteria(@RequestBody IndexElementHistoryCriteria criteria) throws Exception {
        return super.findHistoryPaginatedByCriteria(criteria);
    }

    @Operation(summary = "Exports indexElement history by criteria")
    @PostMapping("export-history")
    public ResponseEntity<InputStreamResource> exportHistory(@RequestBody IndexElementHistoryCriteria criteria) throws Exception {
        return super.exportHistory(criteria);
    }

    @Operation(summary = "Gets indexElement history data size by criteria")
    @PostMapping("history-data-size")
    public ResponseEntity<Integer> getHistoryDataSize(@RequestBody IndexElementHistoryCriteria criteria) throws Exception {
        return super.getHistoryDataSize(criteria);
    }
    public IndexElementRestAgent (IndexElementAgentService service, IndexElementConverter converter) {
        super(service, converter);
    }


}