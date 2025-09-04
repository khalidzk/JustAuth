package me.zhyd.oauth.utils;

import com.google.api.client.http.*;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.utils.HttpUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 简化的 HttpTransport，专门用于 Google 公钥获取（只需要 GET）
 */
public class SimpleGoogleHttpTransport extends HttpTransport {

    @Override
    protected LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
        if (!"GET".equalsIgnoreCase(method)) {
            throw new IOException("Only GET method is supported for Google public keys");
        }

        return new LowLevelHttpRequest() {
            private final Map<String, String> headers = new HashMap<>();

            @Override
            public void addHeader(String name, String value) {
                headers.put(name, value);
            }

            @Override
            public LowLevelHttpResponse execute() throws IOException {
                try {
                    // 转换 headers
                    HttpHeader httpHeader = new HttpHeader();
                    for (Map.Entry<String, String> entry : headers.entrySet()) {
                        httpHeader.add(entry.getKey(), entry.getValue());
                    }

                    // 执行 GET 请求
                    HttpUtils utils = new HttpUtils();
                    utils.get(url, null, httpHeader, false);

                    final String responseBody = utils.getBody();
                    final int statusCode = utils.getHttpResponse().getCode();

                    return new LowLevelHttpResponse() {
                        @Override
                        public int getStatusCode() {
                            return statusCode;
                        }

                        @Override
                        public InputStream getContent() throws IOException {
                            return new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8));
                        }

                        @Override
                        public String getContentEncoding() throws IOException {
                            return "UTF-8";
                        }

                        @Override
                        public long getContentLength() throws IOException {
                            return responseBody.getBytes(StandardCharsets.UTF_8).length;
                        }

                        @Override
                        public String getContentType() throws IOException {
                            return "application/json";
                        }

                        @Override
                        public String getStatusLine() throws IOException {
                            return "HTTP/1.1 " + statusCode + " OK";
                        }

                        @Override
                        public String getReasonPhrase() throws IOException {
                            return statusCode == 200 ? "OK" : "Error";
                        }

                        @Override
                        public int getHeaderCount() throws IOException {
                            return 2;
                        }

                        @Override
                        public String getHeaderName(int index) throws IOException {
                            return index == 0 ? "Content-Type" : "Content-Length";
                        }

                        @Override
                        public String getHeaderValue(int index) throws IOException {
                            return index == 0 ? "application/json" :
                                String.valueOf(responseBody.getBytes(StandardCharsets.UTF_8).length);
                        }
                    };

                } catch (Exception e) {
                    throw new IOException("Failed to fetch Google public keys: " + e.getMessage(), e);
                }
            }
        };
    }

    @Override
    public boolean supportsMethod(String method) throws IOException {
        return "GET".equalsIgnoreCase(method);
    }
}
