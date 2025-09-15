package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xkcoding.http.HttpUtil;
import com.xkcoding.http.support.SimpleHttpResponse;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import okhttp3.Request;

/**
 * Apple Jwt token登录
 *
 * @author zhengkai
 * @since 1.16.7
 */
public class AuthAppleAppRequest extends AuthDefaultAppRequest {

    private static final String APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public AuthAppleAppRequest(AuthConfig config) {
        super(config, AuthDefaultSource.APPLE_APP);
    }

    public AuthAppleAppRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.APPLE_APP, authStateCache);
    }


    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        throw new AuthException(AuthResponseStatus.NOT_IMPLEMENTED, source);
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        throw new AuthException(AuthResponseStatus.NOT_IMPLEMENTED, source);
    }

    @Override
    public AuthUser verifyAppToken(String appToken) {
        try {
            Claims claims = verifyIdentityToken(appToken);
            return extractUserInfo(claims);
        } catch (Exception e) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_CODE, source);
        }
    }

    /**
     * 验证苹果身份令牌
     */
    private Claims verifyIdentityToken(String identityToken) throws Exception {
        // 1. 解码JWT的三个部分
        String[] jwtParts = identityToken.split("\\.");
        if (jwtParts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format");
        }

        // 解析Header获取kid和alg
        String headerJson = new String(Base64.getUrlDecoder().decode(jwtParts[0]));
        Map<String, Object> header = OBJECT_MAPPER.readValue(headerJson, Map.class);
        String kid = (String) header.get("kid");
        String alg = (String) header.get("alg");

        if (!"RS256".equals(alg)) {
            throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }

        // 2. 获取苹果公钥
        PublicKey publicKey = getApplePublicKey(kid);

        // 3. 验证JWT - Java 1.8 兼容方式
        Claims claims = parseAndVerifyJwt(identityToken, publicKey);

        // 4. 验证claims
        //        validateClaims(claims, clientId);

        return claims;
    }

    /**
     * Java 1.8 兼容的JWT解析和验证方法
     */
    private Claims parseAndVerifyJwt(String jwt, PublicKey publicKey) {
        try {
            // 使用旧版API
            return Jwts.parser()
                .setSigningKey(publicKey).build()
                .parseClaimsJws(jwt)
                .getBody();
        } catch (Exception e) {
            throw new RuntimeException("JWT verification failed", e);
        }
    }

    /**
     * 从苹果获取公钥
     */
    private PublicKey getApplePublicKey(String kid) throws Exception {
        Request request = new Request.Builder()
            .url(APPLE_KEYS_URL)
            .get()
            .build();
        SimpleHttpResponse response = HttpUtil.get(APPLE_KEYS_URL);
        if (!response.isSuccess()) {
            throw new RuntimeException("Failed to fetch Apple public keys: " + response.getCode());
        }

        String responseBody = response.getBody();
        Map<String, Object> keysResponse = OBJECT_MAPPER.readValue(responseBody, Map.class);
        List<Map<String, Object>> keys = (List<Map<String, Object>>) keysResponse.get("keys");

        // 查找匹配kid的密钥
        for (Map<String, Object> key : keys) {
            if (kid.equals(key.get("kid"))) {
                return generatePublicKey(key);
            }
        }

        throw new RuntimeException("No matching key found for kid: " + kid);
    }

    /**
     * 生成RSA公钥
     */
    private PublicKey generatePublicKey(Map<String, Object> keyInfo) throws Exception {
        String modulus = (String) keyInfo.get("n");
        String exponent = (String) keyInfo.get("e");
        String keyType = (String) keyInfo.get("kty");

        if (!"RSA".equals(keyType)) {
            throw new RuntimeException("Unsupported key type: " + keyType);
        }

        // Base64Url解码
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);

        BigInteger modulusBigInt = new BigInteger(1, modulusBytes);
        BigInteger exponentBigInt = new BigInteger(1, exponentBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulusBigInt, exponentBigInt);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }

    /**
     * 验证Claims的有效性
     */
    private void validateClaims(Claims claims, String clientId) {
        // 验证发行者
        if (!"https://appleid.apple.com".equals(claims.getIssuer())) {
            throw new RuntimeException("Invalid issuer: " + claims.getIssuer());
        }

        // 验证受众（clientId）
        if (!clientId.equals(claims.getAudience())) {
            throw new RuntimeException("Invalid audience: " + claims.getAudience());
        }

        // 验证过期时间
        if (claims.getExpiration().before(new Date())) {
            throw new RuntimeException("Token has expired");
        }
    }

    /**
     * 仅解码JWT而不验证签名（用于调试）- Java 1.8 兼容
     */
    private Map<String, Object> decodeTokenWithoutVerification(String identityToken) throws Exception {
        String[] parts = identityToken.split("\\.");

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

        Map<String, Object> header = OBJECT_MAPPER.readValue(headerJson, Map.class);
        Map<String, Object> payload = OBJECT_MAPPER.readValue(payloadJson, Map.class);

        // Java 1.8 兼容的Map创建方式
        Map<String, Object> result = new HashMap<>();
        result.put("header", header);
        result.put("payload", payload);
        result.put("signature", parts[2]);

        return result;
    }

    /**
     * 获取用户信息
     */
    private AuthUser extractUserInfo(Claims claims) {
        return AuthUser.builder()
            .uuid((String) claims.get("sub")) //用户的唯一标识符对应APP获取到的：user
            .username((String) claims.get("name"))
//            .nickname(name)
//            .avatar(pictureUrl)
            .email((String) claims.get("email"))
//            .location(locale)
            .gender(AuthUserGender.UNKNOWN)
            .source(source.toString())
//            .token(appToken)
            .rawUserInfo(JSON.parseObject(JSON.toJSONString(claims)))
            .build();
    }
}
