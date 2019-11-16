package org.ikane.demospringjwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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

        // Generate 2048-bit RSA key pair in JWK format, attach some metadata
        RSAKey jwk = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        System.out.println("private key rsa:" + jwk.toRSAPrivateKey());
        System.out.println("-------------------------------------------");
        System.out.println("public key rsa:" + jwk.toRSAPublicKey());

        generateJwtToken();

        //SecretKey secretKey;
        return NimbusJwtDecoder.withPublicKey(jwk.toRSAPublicKey()).build();
    }

    private void generateJwtToken() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("email", "sanjay@example.com")
                .claim("name", "Sanjay Patel")
                .build();

        Payload payload = new Payload(claims.toJSONObject());

        //we are going to use direct encryption with A128CBC_HS256 algorithm. So, the next step is to create an encrypter for it
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        //The secret above is an aes-128-cbc key, generated using an online utility.
        String secret = "841D8A6C80CBA4FCAD32D5367C18C53B";

        byte[] secretKey = secret.getBytes();
        DirectEncrypter encrypter = new DirectEncrypter(secretKey);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(encrypter);
        String token = jweObject.serialize();

        System.out.println(token);
    }
}
