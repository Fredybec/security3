package ma.sir.ged.zynerator.security.ws;


import jakarta.validation.Valid;
import ma.sir.ged.zynerator.security.bean.Role;
import ma.sir.ged.zynerator.security.bean.User;
import ma.sir.ged.zynerator.security.common.SecurityParams;
import ma.sir.ged.zynerator.security.dao.RoleRepository;
import ma.sir.ged.zynerator.security.dao.UserDao;
import ma.sir.ged.zynerator.security.jwt.JwtUtils;
import ma.sir.ged.zynerator.security.payload.request.LoginRequest;
import ma.sir.ged.zynerator.security.payload.request.SignupRequest;
import ma.sir.ged.zynerator.security.payload.response.JwtResponse;
import ma.sir.ged.zynerator.security.payload.response.MessageResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserDao userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    User userDetails = (User) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());

    HttpHeaders headers = new HttpHeaders();
//    headers.add("Authorization", "Bearer " + jwt); // Adding JWT to the "Authorization" header
//    headers.add("Access-Control-Expose-Headers",
//            "Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Authorization");
    headers.add(SecurityParams.JWT_HEADER_NAME,SecurityParams.HEADER_PREFIX+jwt);// Allowing frontend to access the Authorization header
    return ResponseEntity.ok()
            .headers(headers)
            .body(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
  }


  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
               signUpRequest.getEmail(),
               encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

//    if (strRoles == null) {
//      RoleS userRoleS = roleRepository.findByName(ERole.ROLE_USER)
//          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//      roles.add(userRoleS);
//    } else {
//      strRoles.forEach(role -> {
//        switch (role) {
//        case "admin":
//          Role adminRoleS = roleRepository.findByName(ERole.ROLE_ADMIN)
//              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//          roles.add(adminRoleS);
//
//          break;
//        case "mod":
//          Role modRoleS = roleRepository.findByName(ERole.ROLE_MODERATOR)
//              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//          roles.add(modRoleS);
//
//          break;
//        default:
//          Role userRoleS = roleRepository.findByName(ERole.ROLE_USER)
//              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//          roles.add(userRoleS);
//        }
//      });
//    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }
}
