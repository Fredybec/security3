package ma.sir.ged.zynerator.security.jwt;//package ma.sir.ged.zynerator.security.jwt;//package ma.sir.ged.zynerator.security.jwt;
//
//import com.auth0.jwt.JWT;
//import com.auth0.jwt.algorithms.Algorithm;
//import ma.sir.ged.SpringBootSecurityJwtApplication;
//import ma.sir.ged.zynerator.security.bean.User;
//import ma.sir.ged.zynerator.security.service.facade.UserService;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.Collection;
//import java.util.Date;
//
//
//public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//    private AuthenticationManager authenticationManager;
//
//    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
//        this.authenticationManager = authenticationManager;
//    }
//
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//        try {
//            User myUser = new ObjectMapper().readValue(request.getInputStream(), User.class);
//            System.out.println(myUser.getUsername());
//            System.out.println(myUser.getPassword());
//            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(myUser.getUsername(),myUser.getPassword()));
//        } catch (IOException e) {
//            e.printStackTrace();
//            throw new RuntimeException(e);
//        }
//    }
//
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        User user = (User) authResult.getPrincipal();
//
//        UserService userService = SpringBootSecurityJwtApplication.getCtx().getBean(UserService.class);
//
//        User myUser = userService.findByUsernameWithRoles(user.getUsername());
//
//        Collection<String> roles = new ArrayList<>();
//        if (myUser.getAuthorities() != null) {
//            myUser.getAuthorities().forEach(a->roles.add(a.getAuthority()));
//        }
//        Boolean passwordChanged = myUser.isPasswordChanged();
//        if (passwordChanged == null) {
//            passwordChanged=Boolean.FALSE;
//        }
//        String jwt= JWT.create()
//                .withIssuer(request.getRequestURI())
//                .withSubject(user.getUsername())
//                .withSubject(user.getPrenom())
//                .withSubject(user.getNom())
//                .withArrayClaim("roles",roles.toArray(new String[roles.size()]))
//                .withExpiresAt(new Date(System.currentTimeMillis()+ SecurityParams.EXPIRATION))
//                .withClaim("passwordChanged",passwordChanged)
//                .sign(Algorithm.HMAC256(SecurityParams.SECRET));
//                response.addHeader(SecurityParams.JWT_HEADER_NAME,SecurityParams.HEADER_PREFIX+jwt);
//        System.out.println(jwt);
//    }
//
//}
