package me.zhyd.oauth.request;


import me.zhyd.oauth.cache.AuthDefaultStateCache;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.utils.AuthChecker;

/**
 * 默认的app端request处理类
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @author yangkai.shen (https://xkcoding.com)
 * @since 1.0.0
 */
public abstract class AuthDefaultAppRequest extends AuthDefaultRequest implements AuthAppRequest {
    protected AuthConfig config;
    protected AuthSource source;
    protected AuthStateCache authStateCache;

    public AuthDefaultAppRequest(AuthConfig config, AuthSource source) {
        this(config, source, AuthDefaultStateCache.INSTANCE);
    }

    public AuthDefaultAppRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source);
        this.config = config;
        this.source = source;
        this.authStateCache = authStateCache;
        if (!AuthChecker.isSupportedAuth(config, source)) {
            throw new AuthException(AuthResponseStatus.PARAMETER_INCOMPLETE, source);
        }
        // 校验配置合法性
        this.checkConfig(config);
    }

}
