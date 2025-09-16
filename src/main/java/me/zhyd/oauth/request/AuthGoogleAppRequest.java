package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSON;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.log.Log;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.SimpleGoogleHttpTransport;

/**
 * Google登录
 *
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.3.0
 */
public class AuthGoogleAppRequest extends AuthDefaultAppRequest {

    private final NetHttpTransport transport;
    private final GsonFactory jsonFactory;

    public AuthGoogleAppRequest(AuthConfig config) {
        super(config, AuthDefaultSource.GOOGLE_APP);
        if (config.getHttpConfig() != null && config.getHttpConfig().getProxy() != null) {
            this.transport = new NetHttpTransport.Builder().setProxy(config.getHttpConfig().getProxy()).build();
        } else {
            this.transport = new NetHttpTransport();
        }
        this.jsonFactory = new GsonFactory();
    }

    public AuthGoogleAppRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.GOOGLE_APP, authStateCache);
        if (config.getHttpConfig() != null && config.getHttpConfig().getProxy() != null) {
            this.transport = new NetHttpTransport.Builder().setProxy(config.getHttpConfig().getProxy()).build();
        } else {
            this.transport = new NetHttpTransport();
        }
        this.jsonFactory = new GsonFactory();
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

        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
            .setAudience(config.getClientIds())
            .build();

        GoogleIdToken idToken = null;
        try {
            idToken = verifier.verify(appToken);

            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();

                // Print user identifier
                String userId = payload.getSubject();
                System.out.println("User ID: " + userId);

                // Get profile information from payload
                String email = payload.getEmail();
                boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
                String name = (String) payload.get("name");
                String pictureUrl = (String) payload.get("picture");
                String locale = (String) payload.get("locale");
                String familyName = (String) payload.get("family_name");
                String givenName = (String) payload.get("given_name");

                return AuthUser.builder()
                    .uuid(userId)
                    .username(name)
                    .nickname(name)
                    .avatar(pictureUrl)
                    .email(email)
                    .location(locale)
                    .gender(AuthUserGender.UNKNOWN)
                    .source(source.toString())
                    .token(AuthToken.builder().oauthToken(payload.getAccessTokenHash()).build())
                    .rawUserInfo(JSON.parseObject(JSON.toJSONString(payload)))
                    .build();

            } else {
                Log.error("Invalid ID token.");
            }
        } catch (GeneralSecurityException e) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_CODE, source);
        } catch (IOException e) {
            throw new AuthException(AuthResponseStatus.NOT_IMPLEMENTED, source);
        }

        throw new AuthException(AuthResponseStatus.ILLEGAL_CODE, source);
    }
}
