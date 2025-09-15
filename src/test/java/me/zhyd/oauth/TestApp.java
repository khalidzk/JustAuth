package me.zhyd.oauth;

import com.alibaba.fastjson.JSON;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthAppRequest;
import me.zhyd.oauth.request.AuthAppleAppRequest;
import me.zhyd.oauth.request.AuthAppleRequest;
import me.zhyd.oauth.request.AuthGoogleAppRequest;
import me.zhyd.oauth.request.AuthRequest;
import me.zhyd.oauth.utils.SimpleGoogleHttpTransport;
import org.junit.Test;

/**
 * TODO
 *
 * @author zhengkai
 */
public class TestApp {
    @Test
    public void testGoogleApp() {
        List<String> clientIds = new ArrayList<>();
        clientIds.add("915194632001-h132cjlgfaavh670rp9pe0ed236ajuor.apps.googleusercontent.com");
        clientIds.add("915194632001-6f8mc68a8k2684d9kue1ndftit8jtg82.apps.googleusercontent.com");
        clientIds.add("915194632001-91dl13j58tqtcbi4oc733jn9t9mg8ig9.apps.googleusercontent.com");
        AuthConfig config = AuthConfig.builder()
//                .clientId("")
                .clientIds(clientIds)
                .ignoreCheckRedirectUri(Boolean.TRUE)
                .ignoreSupportedAuth(Boolean.TRUE)
                .build();
        AuthAppRequest request = new AuthGoogleAppRequest(config);
        AuthUser authUser = request.verifyAppToken("eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjA3OGYyNjQ3ZThjZDAxOWM0MGRhOTU2OWU0ZjUyNDc5OTEwOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MTUxOTQ2MzIwMDEtOTFkbDEzajU4dHF0Y2JpNG9jNzMzam45dDltZzhpZzkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5MTUxOTQ2MzIwMDEtOTFkbDEzajU4dHF0Y2JpNG9jNzMzam45dDltZzhpZzkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDIzNjgxNTc5MjAzNzU1MDU3MzUiLCJlbWFpbCI6InpoYW5nMDQwMzQ4QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiSW4xWm5JZXV2YllvNVpOY2l2cEZrUSIsIm5vbmNlIjoiS2MyaGJaNExQbW5QUTdUVlRuYXlxR0RUOXFMdHd0WEUzYllKR3lXeDlEMCIsIm5hbWUiOiLlvKDluIUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSUY5WEtVeUlmSzhXTTRzallsUHI2YUstVUVUa0FBWW9WZklWZUNSZjJUOWpUeE13PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IuW4hSIsImZhbWlseV9uYW1lIjoi5bygIiwiaWF0IjoxNzU3OTI1MDc0LCJleHAiOjE3NTc5Mjg2NzR9.hrW-UytaiVflEtF3GvbatIkjFt8AkyuRgNVdXJZHXsHJU2UBz3qnuflPmJKFRB1KJKdOqKgbgBQjZasI8LutH-OyAPmNuF_HVI2fMDKIjmsTZdZJQZdLEsN8XNpnbQcqgNaDHYDc54YwKAhbR9V4Pb-0wrUWRiwnZo4KAxctVvolM4Ot-oii8vsHu6cAF8tgjyDnLCHiGA6tC4XuoylQ8Hanq1qsA3yxr4RSQTz2n49Z40iChdKowU5_BiuKD_0YHwXefDw0aORltjVeoBYIUm51mapbRpWJfuLoFiyIDl5ydcljHWZotH2GMhmGNgHkbHuwNX-U8MrOfrJ7Q4sJUA");
        System.out.println(JSON.toJSONString(authUser, true));
    }

    @org.junit.Test
    public void test1() throws GeneralSecurityException, IOException {

        List<String> clientIds = new ArrayList<>();
        clientIds.add("915194632001-h132cjlgfaavh670rp9pe0ed236ajuor.apps.googleusercontent.com");
        clientIds.add("915194632001-6f8mc68a8k2684d9kue1ndftit8jtg82.apps.googleusercontent.com");
        clientIds.add("915194632001-91dl13j58tqtcbi4oc733jn9t9mg8ig9.apps.googleusercontent.com");

        // 使用 NetHttpTransport 而不是 SimpleGoogleHttpTransport
        NetHttpTransport transport = new NetHttpTransport();
        GsonFactory jsonFactory = new GsonFactory();
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
            // Specify the WEB_CLIENT_ID of the app that accesses the backend:
            .setAudience(clientIds)
            // Or, if multiple clients access the backend:
            //.setAudience(Arrays.asList(WEB_CLIENT_ID_1, WEB_CLIENT_ID_2, WEB_CLIENT_ID_3))
            .build();
        // (Receive idTokenString by HTTPS POST)
        GoogleIdToken idToken = verifier.verify("eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjA3OGYyNjQ3ZThjZDAxOWM0MGRhOTU2OWU0ZjUyNDc5OTEwOTQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MTUxOTQ2MzIwMDEtOTFkbDEzajU4dHF0Y2JpNG9jNzMzam45dDltZzhpZzkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5MTUxOTQ2MzIwMDEtOTFkbDEzajU4dHF0Y2JpNG9jNzMzam45dDltZzhpZzkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDIzNjgxNTc5MjAzNzU1MDU3MzUiLCJlbWFpbCI6InpoYW5nMDQwMzQ4QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiSW4xWm5JZXV2YllvNVpOY2l2cEZrUSIsIm5vbmNlIjoiS2MyaGJaNExQbW5QUTdUVlRuYXlxR0RUOXFMdHd0WEUzYllKR3lXeDlEMCIsIm5hbWUiOiLlvKDluIUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSUY5WEtVeUlmSzhXTTRzallsUHI2YUstVUVUa0FBWW9WZklWZUNSZjJUOWpUeE13PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IuW4hSIsImZhbWlseV9uYW1lIjoi5bygIiwiaWF0IjoxNzU3OTI1MDc0LCJleHAiOjE3NTc5Mjg2NzR9.hrW-UytaiVflEtF3GvbatIkjFt8AkyuRgNVdXJZHXsHJU2UBz3qnuflPmJKFRB1KJKdOqKgbgBQjZasI8LutH-OyAPmNuF_HVI2fMDKIjmsTZdZJQZdLEsN8XNpnbQcqgNaDHYDc54YwKAhbR9V4Pb-0wrUWRiwnZo4KAxctVvolM4Ot-oii8vsHu6cAF8tgjyDnLCHiGA6tC4XuoylQ8Hanq1qsA3yxr4RSQTz2n49Z40iChdKowU5_BiuKD_0YHwXefDw0aORltjVeoBYIUm51mapbRpWJfuLoFiyIDl5ydcljHWZotH2GMhmGNgHkbHuwNX-U8MrOfrJ7Q4sJUA");
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

            // Use or store profile information
            // ...
            System.out.println(JSON.toJSONString(payload));

        } else {
            System.out.println("Invalid ID token.");
        }
    }

    @Test
    public void testAppleApp() {
        AuthConfig config = AuthConfig.builder()
            //                .clientId("")
//            .clientIds(clientIds)
            .ignoreCheckRedirectUri(Boolean.TRUE)
            .ignoreSupportedAuth(Boolean.TRUE)
            .build();
        AuthAppRequest request = new AuthAppleAppRequest(config);
        AuthUser authUser = request.verifyAppToken("eyJraWQiOiJVYUlJRlkyZlc0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmRvcmEuZG9yYSIsImV4cCI6MTc1ODAyNzE2MSwiaWF0IjoxNzU3OTQwNzYxLCJzdWIiOiIwMDE2MTAuZDg2NjhjODkzMmZkNGRmZmJjYmNkYmUxMzhmNzZmY2EuMDIxMCIsImNfaGFzaCI6InFxdGFlem9ab3hxdU90c0huQlZ2aGciLCJlbWFpbCI6InVhb3UwNmF5YTI2Mzc2QDEyNi5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXV0aF90aW1lIjoxNzU3OTQwNzYxLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.WFZjNBMwYDxkp9N6BuIKjqYULzQUes9nqw3-cS2KjPs-oLPT0GYAzFQ3MLIyOgg-n7qnsEQjeGlz7GejMFLUYLoN6lnwCnDF-n_1QxuMaBy4ZAZM-6svxtsi0C_1A31ZoLiqUSL_VwGuSFBmbZMflnL9kgwVVd-iyLlFe3DE5ZpYmjjP48hR_zBOhuiAKejIAt3LniZl9B2DZRB428X9eumfaQDhI6dj2V0ZD62bLJRbAaaXT1Dkdv9QfZobeDMlTZr457kjZyCEHUJMWRcNbzqPBOi9HJP5hDxK86Kb-gOIofsRgYnTzmvJvqfZcNtheYfxXO9TJf4DyXiH7OzRVg");
        System.out.println(JSON.toJSONString(authUser, true));
    }

}
