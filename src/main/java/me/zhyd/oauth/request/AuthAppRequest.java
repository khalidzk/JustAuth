package me.zhyd.oauth.request;

import me.zhyd.oauth.model.AuthUser;

/**
 * JustAuth {@code Request}公共接口，所有平台的{@code Request}都需要实现该接口
 * <p>
 * {@link AuthAppRequest#authorize()}
 * {@link AuthAppRequest#authorize(String)}
 * {@link AuthAppRequest#login(me.zhyd.oauth.model.AuthCallback)}
 * {@link AuthAppRequest#revoke(me.zhyd.oauth.model.AuthToken)}
 * {@link AuthAppRequest#refresh(me.zhyd.oauth.model.AuthToken)}
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.8
 */
public interface AuthAppRequest extends AuthRequest {
    /**
     * 验证APP端传过来的token换取用户信息
     *
     * @param appToken app端传递的token信息
     * @return 用户信息
     */
    AuthUser verifyAppToken(String appToken);
}
