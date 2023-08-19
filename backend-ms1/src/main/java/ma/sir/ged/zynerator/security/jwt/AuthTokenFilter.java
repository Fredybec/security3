package ma.sir.ged.zynerator.security.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import ma.sir.ged.zynerator.security.common.SecurityParams;
import ma.sir.ged.zynerator.security.service.facade.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        response.addHeader("Access-Control-Allow-Origin", "*");// Angular :: "http://localhost:4200" or React :: "http://localhost:3000"
        response.addHeader("Access-Control-Allow-Headers",
                "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers,Authorization");
        response.addHeader("Access-Control-Allow-Methods", "DELETE, POST, GET, PUT, PATCH, OPTIONS");
        response.addHeader("Access-Control-Expose-Headers",
                "Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Authorization");
        try {
            if (request.getMethod().equals("OPTIONS")) {
                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                String jwtToken = request.getHeader(SecurityParams.JWT_HEADER_NAME);
                String jwt = jwtToken.substring(SecurityParams.HEADER_PREFIX.length());
                System.out.println("Token=" + jwtToken);
                if (jwt == null || !jwtToken.startsWith(SecurityParams.HEADER_PREFIX)) {
                    filterChain.doFilter(request, response);
                    return;
                }
//            String jwt = parseJwt(request);
//            && jwtUtils.validateJwtToken(jwt)
                else {
                    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();
                    DecodedJWT decodedJWT = verifier.verify(jwt);
                    String username = decodedJWT.getSubject();
//                        jwtUtils.getUserNameFromJwtToken(jwt);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);
                    System.out.println("username=" + username);
                    System.out.println("roles=" + roles);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    roles.forEach(rn -> {
                        authorities.add(new SimpleGrantedAuthority(rn));
                    });
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
//            response.addHeader("Access-Control-Allow-Origin", "*");// Angular :: "http://localhost:4200" or React :: "http://localhost:3000"
//            response.addHeader("Access-Control-Allow-Headers",
//                    "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers,Authorization");
//            response.addHeader("Access-Control-Allow-Methods", "DELETE, POST, GET, PUT, PATCH, OPTIONS");
//            response.addHeader("Access-Control-Expose-Headers",
//                    "Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Authorization");
//
//            if (request.getMethod().equals("OPTIONS")) {
//                response.setStatus(HttpServletResponse.SC_OK);
//            } else if (request.getRequestURI().equals("/login")) {
//                filterChain.doFilter(request, response);
//                return;
//            } else {
//                String jwtToken = request.getHeader(SecurityParams.JWT_HEADER_NAME);
//                System.out.println("Token=" + jwtToken);
//                if (jwtToken == null || !jwtToken.startsWith(SecurityParams.HEADER_PREFIX)) {
//                    filterChain.doFilter(request, response);
//                    return;
//                }
//                JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();
//                String jwt = jwtToken.substring(SecurityParams.HEADER_PREFIX.length());
//                DecodedJWT decodedJWT = verifier.verify(jwt);
//                System.out.println("JWT=" + jwt);
//                String username = decodedJWT.getSubject();
//                List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);
//                System.out.println("username=" + username);
//                System.out.println("roles=" + roles);
//                Collection<GrantedAuthority> authorities = new ArrayList<>();
//                roles.forEach(rn -> {
//                    authorities.add(new SimpleGrantedAuthority(rn));
//                });
//                UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username, null, authorities);
//                SecurityContextHolder.getContext().setAuthentication(user);
//                filterChain.doFilter(request, response);
//            }
    }


    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}
