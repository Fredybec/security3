package  ma.sir.ged;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import java.util.*;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Autowired;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import org.springframework.cache.annotation.EnableCaching;


import ma.sir.ged.bean.core.*;
import ma.sir.ged.service.facade.admin.*;

import ma.sir.ged.zynerator.security.common.AuthoritiesConstants;
import ma.sir.ged.zynerator.security.bean.User;
import ma.sir.ged.zynerator.security.bean.Permission;
import ma.sir.ged.zynerator.security.bean.Role;
import ma.sir.ged.zynerator.security.service.facade.UserService;
import ma.sir.ged.zynerator.security.service.facade.RoleService;


import org.springframework.web.client.RestTemplate;

@SpringBootApplication
@EnableCaching
//@EnableFeignClients("ma.sir.ged.required.facade")
public class GedApplication {
    public static ConfigurableApplicationContext ctx;

    public static void main(String[] args) {
        ctx=SpringApplication.run(GedApplication.class, args);
    }


    @Bean
    RestTemplate restTemplate(){
        return new RestTemplate();
    }
    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    ObjectMapper objectMapper(){
        return new ObjectMapper();
    }
    public static ConfigurableApplicationContext getCtx() {
        return ctx;
    }

    @Bean
    public CommandLineRunner demo(UserService userService, RoleService roleService) {
    return (args) -> {
        if(false){



    // Role admin

        User userForAdmin = new User("admin");

        Role roleForAdmin = new Role();
        roleForAdmin.setAuthority(AuthoritiesConstants.ADMIN);
        List<Permission> permissionsForAdmin = new ArrayList<>();
        addPermissionForAdmin(permissionsForAdmin);
        roleForAdmin.setPermissions(permissionsForAdmin);
        if(userForAdmin.getRoles()==null)
            userForAdmin.setRoles(new ArrayList<>());

        userForAdmin.getRoles().add(roleForAdmin);
        userService.save(userForAdmin);


    // Role agent

        User userForAgent = new User("agent");

        Role roleForAgent = new Role();
        roleForAgent.setAuthority(AuthoritiesConstants.AGENT);
        List<Permission> permissionsForAgent = new ArrayList<>();
        addPermissionForAgent(permissionsForAgent);
        roleForAgent.setPermissions(permissionsForAgent);
        if(userForAgent.getRoles()==null)
            userForAgent.setRoles(new ArrayList<>());

        userForAgent.getRoles().add(roleForAgent);
        userService.save(userForAgent);
            }
        };
    }




    private static String fakeString(String attributeName, int i) {
        return attributeName + i;
    }

    private static Long fakeLong(String attributeName, int i) {
        return  10L * i;
    }
    private static Integer fakeInteger(String attributeName, int i) {
        return  10 * i;
    }

    private static Double fakeDouble(String attributeName, int i) {
        return 10D * i;
    }

    private static BigDecimal fakeBigDecimal(String attributeName, int i) {
        return  BigDecimal.valueOf(i*1L*10);
    }

    private static Boolean fakeBoolean(String attributeName, int i) {
        return i % 2 == 0 ? true : false;
    }
    private static LocalDateTime fakeLocalDateTime(String attributeName, int i) {
        return LocalDateTime.now().plusDays(i);
    }
    private static void addPermissionForAdmin(List<Permission> permissions){
        permissions.add(new Permission("DocumentPartageGroupe.edit"));
        permissions.add(new Permission("DocumentPartageGroupe.list"));
        permissions.add(new Permission("DocumentPartageGroupe.view"));
        permissions.add(new Permission("DocumentPartageGroupe.add"));
        permissions.add(new Permission("DocumentPartageGroupe.delete"));
        permissions.add(new Permission("EtatUtilisateur.edit"));
        permissions.add(new Permission("EtatUtilisateur.list"));
        permissions.add(new Permission("EtatUtilisateur.view"));
        permissions.add(new Permission("EtatUtilisateur.add"));
        permissions.add(new Permission("EtatUtilisateur.delete"));
        permissions.add(new Permission("GroupeUtilisateur.edit"));
        permissions.add(new Permission("GroupeUtilisateur.list"));
        permissions.add(new Permission("GroupeUtilisateur.view"));
        permissions.add(new Permission("GroupeUtilisateur.add"));
        permissions.add(new Permission("GroupeUtilisateur.delete"));
        permissions.add(new Permission("RoleUtilisateur.edit"));
        permissions.add(new Permission("RoleUtilisateur.list"));
        permissions.add(new Permission("RoleUtilisateur.view"));
        permissions.add(new Permission("RoleUtilisateur.add"));
        permissions.add(new Permission("RoleUtilisateur.delete"));
        permissions.add(new Permission("Document.edit"));
        permissions.add(new Permission("Document.list"));
        permissions.add(new Permission("Document.view"));
        permissions.add(new Permission("Document.add"));
        permissions.add(new Permission("Document.delete"));
        permissions.add(new Permission("DocumentIndexElement.edit"));
        permissions.add(new Permission("DocumentIndexElement.list"));
        permissions.add(new Permission("DocumentIndexElement.view"));
        permissions.add(new Permission("DocumentIndexElement.add"));
        permissions.add(new Permission("DocumentIndexElement.delete"));
        permissions.add(new Permission("EntiteAdministrativeType.edit"));
        permissions.add(new Permission("EntiteAdministrativeType.list"));
        permissions.add(new Permission("EntiteAdministrativeType.view"));
        permissions.add(new Permission("EntiteAdministrativeType.add"));
        permissions.add(new Permission("EntiteAdministrativeType.delete"));
        permissions.add(new Permission("DocumentPartageUtilisateur.edit"));
        permissions.add(new Permission("DocumentPartageUtilisateur.list"));
        permissions.add(new Permission("DocumentPartageUtilisateur.view"));
        permissions.add(new Permission("DocumentPartageUtilisateur.add"));
        permissions.add(new Permission("DocumentPartageUtilisateur.delete"));
        permissions.add(new Permission("DocumentCategorie.edit"));
        permissions.add(new Permission("DocumentCategorie.list"));
        permissions.add(new Permission("DocumentCategorie.view"));
        permissions.add(new Permission("DocumentCategorie.add"));
        permissions.add(new Permission("DocumentCategorie.delete"));
        permissions.add(new Permission("DocumentCategorieModel.edit"));
        permissions.add(new Permission("DocumentCategorieModel.list"));
        permissions.add(new Permission("DocumentCategorieModel.view"));
        permissions.add(new Permission("DocumentCategorieModel.add"));
        permissions.add(new Permission("DocumentCategorieModel.delete"));
        permissions.add(new Permission("Groupe.edit"));
        permissions.add(new Permission("Groupe.list"));
        permissions.add(new Permission("Groupe.view"));
        permissions.add(new Permission("Groupe.add"));
        permissions.add(new Permission("Groupe.delete"));
        permissions.add(new Permission("DocumentTag.edit"));
        permissions.add(new Permission("DocumentTag.list"));
        permissions.add(new Permission("DocumentTag.view"));
        permissions.add(new Permission("DocumentTag.add"));
        permissions.add(new Permission("DocumentTag.delete"));
        permissions.add(new Permission("Utilisateur.edit"));
        permissions.add(new Permission("Utilisateur.list"));
        permissions.add(new Permission("Utilisateur.view"));
        permissions.add(new Permission("Utilisateur.add"));
        permissions.add(new Permission("Utilisateur.delete"));
        permissions.add(new Permission("Tag.edit"));
        permissions.add(new Permission("Tag.list"));
        permissions.add(new Permission("Tag.view"));
        permissions.add(new Permission("Tag.add"));
        permissions.add(new Permission("Tag.delete"));
        permissions.add(new Permission("DocumentCategorieIndex.edit"));
        permissions.add(new Permission("DocumentCategorieIndex.list"));
        permissions.add(new Permission("DocumentCategorieIndex.view"));
        permissions.add(new Permission("DocumentCategorieIndex.add"));
        permissions.add(new Permission("DocumentCategorieIndex.delete"));
        permissions.add(new Permission("DocumentState.edit"));
        permissions.add(new Permission("DocumentState.list"));
        permissions.add(new Permission("DocumentState.view"));
        permissions.add(new Permission("DocumentState.add"));
        permissions.add(new Permission("DocumentState.delete"));
        permissions.add(new Permission("Gender.edit"));
        permissions.add(new Permission("Gender.list"));
        permissions.add(new Permission("Gender.view"));
        permissions.add(new Permission("Gender.add"));
        permissions.add(new Permission("Gender.delete"));
        permissions.add(new Permission("AccessShare.edit"));
        permissions.add(new Permission("AccessShare.list"));
        permissions.add(new Permission("AccessShare.view"));
        permissions.add(new Permission("AccessShare.add"));
        permissions.add(new Permission("AccessShare.delete"));
        permissions.add(new Permission("DocumentType.edit"));
        permissions.add(new Permission("DocumentType.list"));
        permissions.add(new Permission("DocumentType.view"));
        permissions.add(new Permission("DocumentType.add"));
        permissions.add(new Permission("DocumentType.delete"));
        permissions.add(new Permission("DocumentCategorieIndexRule.edit"));
        permissions.add(new Permission("DocumentCategorieIndexRule.list"));
        permissions.add(new Permission("DocumentCategorieIndexRule.view"));
        permissions.add(new Permission("DocumentCategorieIndexRule.add"));
        permissions.add(new Permission("DocumentCategorieIndexRule.delete"));
        permissions.add(new Permission("IndexElement.edit"));
        permissions.add(new Permission("IndexElement.list"));
        permissions.add(new Permission("IndexElement.view"));
        permissions.add(new Permission("IndexElement.add"));
        permissions.add(new Permission("IndexElement.delete"));
        permissions.add(new Permission("EntiteAdministrative.edit"));
        permissions.add(new Permission("EntiteAdministrative.list"));
        permissions.add(new Permission("EntiteAdministrative.view"));
        permissions.add(new Permission("EntiteAdministrative.add"));
        permissions.add(new Permission("EntiteAdministrative.delete"));
    }
    private static void addPermissionForAgent(List<Permission> permissions){
        permissions.add(new Permission("DocumentPartageGroupe.edit"));
        permissions.add(new Permission("DocumentPartageGroupe.list"));
        permissions.add(new Permission("DocumentPartageGroupe.view"));
        permissions.add(new Permission("DocumentPartageGroupe.add"));
        permissions.add(new Permission("DocumentPartageGroupe.delete"));
        permissions.add(new Permission("EtatUtilisateur.edit"));
        permissions.add(new Permission("EtatUtilisateur.list"));
        permissions.add(new Permission("EtatUtilisateur.view"));
        permissions.add(new Permission("EtatUtilisateur.add"));
        permissions.add(new Permission("EtatUtilisateur.delete"));
        permissions.add(new Permission("GroupeUtilisateur.edit"));
        permissions.add(new Permission("GroupeUtilisateur.list"));
        permissions.add(new Permission("GroupeUtilisateur.view"));
        permissions.add(new Permission("GroupeUtilisateur.add"));
        permissions.add(new Permission("GroupeUtilisateur.delete"));
        permissions.add(new Permission("RoleUtilisateur.edit"));
        permissions.add(new Permission("RoleUtilisateur.list"));
        permissions.add(new Permission("RoleUtilisateur.view"));
        permissions.add(new Permission("RoleUtilisateur.add"));
        permissions.add(new Permission("RoleUtilisateur.delete"));
        permissions.add(new Permission("Document.edit"));
        permissions.add(new Permission("Document.list"));
        permissions.add(new Permission("Document.view"));
        permissions.add(new Permission("Document.add"));
        permissions.add(new Permission("Document.delete"));
        permissions.add(new Permission("DocumentIndexElement.edit"));
        permissions.add(new Permission("DocumentIndexElement.list"));
        permissions.add(new Permission("DocumentIndexElement.view"));
        permissions.add(new Permission("DocumentIndexElement.add"));
        permissions.add(new Permission("DocumentIndexElement.delete"));
        permissions.add(new Permission("EntiteAdministrativeType.edit"));
        permissions.add(new Permission("EntiteAdministrativeType.list"));
        permissions.add(new Permission("EntiteAdministrativeType.view"));
        permissions.add(new Permission("EntiteAdministrativeType.add"));
        permissions.add(new Permission("EntiteAdministrativeType.delete"));
        permissions.add(new Permission("DocumentPartageUtilisateur.edit"));
        permissions.add(new Permission("DocumentPartageUtilisateur.list"));
        permissions.add(new Permission("DocumentPartageUtilisateur.view"));
        permissions.add(new Permission("DocumentPartageUtilisateur.add"));
        permissions.add(new Permission("DocumentPartageUtilisateur.delete"));
        permissions.add(new Permission("DocumentCategorie.edit"));
        permissions.add(new Permission("DocumentCategorie.list"));
        permissions.add(new Permission("DocumentCategorie.view"));
        permissions.add(new Permission("DocumentCategorie.add"));
        permissions.add(new Permission("DocumentCategorie.delete"));
        permissions.add(new Permission("DocumentCategorieModel.edit"));
        permissions.add(new Permission("DocumentCategorieModel.list"));
        permissions.add(new Permission("DocumentCategorieModel.view"));
        permissions.add(new Permission("DocumentCategorieModel.add"));
        permissions.add(new Permission("DocumentCategorieModel.delete"));
        permissions.add(new Permission("Groupe.edit"));
        permissions.add(new Permission("Groupe.list"));
        permissions.add(new Permission("Groupe.view"));
        permissions.add(new Permission("Groupe.add"));
        permissions.add(new Permission("Groupe.delete"));
        permissions.add(new Permission("DocumentTag.edit"));
        permissions.add(new Permission("DocumentTag.list"));
        permissions.add(new Permission("DocumentTag.view"));
        permissions.add(new Permission("DocumentTag.add"));
        permissions.add(new Permission("DocumentTag.delete"));
        permissions.add(new Permission("Utilisateur.edit"));
        permissions.add(new Permission("Utilisateur.list"));
        permissions.add(new Permission("Utilisateur.view"));
        permissions.add(new Permission("Utilisateur.add"));
        permissions.add(new Permission("Utilisateur.delete"));
        permissions.add(new Permission("Tag.edit"));
        permissions.add(new Permission("Tag.list"));
        permissions.add(new Permission("Tag.view"));
        permissions.add(new Permission("Tag.add"));
        permissions.add(new Permission("Tag.delete"));
        permissions.add(new Permission("DocumentCategorieIndex.edit"));
        permissions.add(new Permission("DocumentCategorieIndex.list"));
        permissions.add(new Permission("DocumentCategorieIndex.view"));
        permissions.add(new Permission("DocumentCategorieIndex.add"));
        permissions.add(new Permission("DocumentCategorieIndex.delete"));
        permissions.add(new Permission("DocumentState.edit"));
        permissions.add(new Permission("DocumentState.list"));
        permissions.add(new Permission("DocumentState.view"));
        permissions.add(new Permission("DocumentState.add"));
        permissions.add(new Permission("DocumentState.delete"));
        permissions.add(new Permission("Gender.edit"));
        permissions.add(new Permission("Gender.list"));
        permissions.add(new Permission("Gender.view"));
        permissions.add(new Permission("Gender.add"));
        permissions.add(new Permission("Gender.delete"));
        permissions.add(new Permission("AccessShare.edit"));
        permissions.add(new Permission("AccessShare.list"));
        permissions.add(new Permission("AccessShare.view"));
        permissions.add(new Permission("AccessShare.add"));
        permissions.add(new Permission("AccessShare.delete"));
        permissions.add(new Permission("DocumentType.edit"));
        permissions.add(new Permission("DocumentType.list"));
        permissions.add(new Permission("DocumentType.view"));
        permissions.add(new Permission("DocumentType.add"));
        permissions.add(new Permission("DocumentType.delete"));
        permissions.add(new Permission("DocumentCategorieIndexRule.edit"));
        permissions.add(new Permission("DocumentCategorieIndexRule.list"));
        permissions.add(new Permission("DocumentCategorieIndexRule.view"));
        permissions.add(new Permission("DocumentCategorieIndexRule.add"));
        permissions.add(new Permission("DocumentCategorieIndexRule.delete"));
        permissions.add(new Permission("IndexElement.edit"));
        permissions.add(new Permission("IndexElement.list"));
        permissions.add(new Permission("IndexElement.view"));
        permissions.add(new Permission("IndexElement.add"));
        permissions.add(new Permission("IndexElement.delete"));
        permissions.add(new Permission("EntiteAdministrative.edit"));
        permissions.add(new Permission("EntiteAdministrative.list"));
        permissions.add(new Permission("EntiteAdministrative.view"));
        permissions.add(new Permission("EntiteAdministrative.add"));
        permissions.add(new Permission("EntiteAdministrative.delete"));
    }

}


