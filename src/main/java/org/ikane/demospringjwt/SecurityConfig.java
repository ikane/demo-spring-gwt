package org.ikane.demospringjwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private RSAKey rsaJWK;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //@formatter:off
        http
                .cors()
                .and()
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                  .anyRequest()
                    .authenticated()
                .and()
                .oauth2ResourceServer()
                    .jwt()
                    .decoder(decoder())

        ;
        //@formatter:on
    }

    private JwtDecoder decoder() throws Exception {

        // RSA signatures require a public and private RSA key pair, the public key
        // must be made known to the JWS recipient in order to verify the signatures
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        String token = generateJwtToken();
        System.out.println("JWT token:" + token);

        return NimbusJwtDecoder.withPublicKey(rsaPublicJWK.toRSAPublicKey()).build();
    }

    private String generateJwtToken() throws JOSEException {
        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("ikane")
                .issuer("https://ikane.org")
                .claim("uid-local", "123456789")
                .expirationTime(Date.from(Instant.now().plus(4, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    @Bean
    public RSAKey rsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                    .keyID("123")
                    .generate();
    }

}
