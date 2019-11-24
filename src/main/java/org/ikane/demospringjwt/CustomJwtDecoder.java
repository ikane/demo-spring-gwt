package org.ikane.demospringjwt;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Collections;
import java.util.Map;

@Slf4j
@Component
public class CustomJwtDecoder implements JwtDecoder {

    private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter =
            MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    @Override
    public Jwt decode(String token) throws JwtException {

        log.info("Decoding token: {}", token);

        try {
            //Base64URL[] parts = JOSEObject.split(token);
            JWT jwt = JWTParser.parse(token);

            //jwt.
            PlainJWT plainJWT = new PlainJWT(jwt.getJWTClaimsSet());

            Map<String, Object> claims = this.claimSetConverter.convert(plainJWT.getJWTClaimsSet().getClaims());

            return Jwt.withTokenValue(token)
                    .claims(c -> c.putAll(claims))
                    .build()
                    ;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
