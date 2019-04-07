const urllib = require('urllib');
const crypto = require('crypto');
const {APIError} = require('./Errors');

class API {
  constructor({appid, secret}) {
    if (!appid) throw new Error('ERR_APPID_FAIL');
    if (!secret) throw new Error('ERR_SECRET_FAIL');

    this.appid = appid;
    this.secret = secret;
  }

  /**
   * 存储ACCESS_TOKEN
   * @example 重写
   * instance._setToken = Function
   *
   * @author Eric
   * @param  {Object} token ACCESS_TOKEN对象
   */
  async _setToken(token) {
    this._accessToken = token;
  }

  /**
   * 获取ACCESS_TOKEN
   * @example 重写
   * instance._getToken = Function
   *
   * @author Eric
   * @return {string} Token值
   */
  async _getToken() {
    let token = this._accessToken;
    if (!token || token.expires_in < (Date.now() / 1000 | 0) - 600) token = await this.getAccessToken();
    return token.access_token;
  }

  /**
   * 加密信息解密
   * @author Eric
   * @param  {String} encryptedData 加密信息
   * @param  {String} key           密钥
   * @param  {String} iv            向量
   * @return {Object}               解密后信息
   */
  decrypt(encryptedData, key, iv) {
    key = Buffer.from(key, 'base64');
    iv = Buffer.from(iv, 'base64');
    let decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        decipher.setAutoPadding(true);
    let decoded = decipher.update(encryptedData, 'base64', 'utf8');
        decoded += decipher.final('utf8');
    return JSON.parse(decoded);
  }

  /**
   * 获取openid, session_key, unionid
   * @author Eric
   * @param  {String} code CODE值
   * @return {Object}      openid/session_key/unionid
   */
  async code2Session(code) {
    const URI = 'https://api.weixin.qq.com/sns/jscode2session';

    let {status, data} = await urllib.request(URI, {
      method: 'GET',
      dataType: 'json',
      data: {
        grant_type: 'authorization_code',
        appid: this.appid,
        secret: this.secret,
        js_code: code
      }
    });
    if (status !== 200) throw new Error('ERR_REQUEST');
    if (data.errcode) throw new APIError(data.errcode, data.errmsg);
    return data;
  }

  /**
   * 获取AccessToken
   * @author Eric
   * @return {Object} {access_token, expire_in}
   */
  async getAccessToken() {
    const URI = 'https://api.weixin.qq.com/cgi-bin/token';

    let pkg = {
      grant_type: 'client_credential',
      appid: this.appid,
      secret: this.secret
    };

    let {status, data} = await urllib.request(URI, {
      method: 'GET',
      dataType: 'json',
      data: pkg
    });

    if (status !== 200) throw new Error('ERR_REQUEST');
    if (data.errcode) throw new APIError(data.errcode, data.errmsg);
    await this._setToken(data);
    return data;
  }

  /**
   * 获取unionid(支付成功5分钟内)
   * @author Eric
   * @param  {Object} params 参数
   * @return {Object}        {errcode, errmsg, unionid}
   */
  async getPaidUnionId(params) {
    let access_token = await this._getToken();
    let URI = 'https://api.weixin.qq.com/wxa/getpaidunionid';

    let pkg = {
      ...params,
      access_token
    };
    let {status, data} = await urllib.request(URI, {
      method: 'GET',
      dataType: 'json',
      data: pkg
    });
    if (status !== 200) throw new Error('ERR_REQUEST');
    if (data.errcode) throw new APIError(data.errcode, data.errmsg);
    return data;
  }

  /**
   * 发送统一服务消息
   * @author Eric
   * @param  {Object} params 参数
   * @return {Object}        {errcode, errmsg}
   */
  async uniformMessageSend(params) {
    let access_token = await this._getToken();
    let URI = `https://api.weixin.qq.com/cgi-bin/message/wxopen/template/uniform_send?access_token=${access_token}`;

    let {status, data} = await urllib.request(URI, {
      method: 'post',
      contentType: 'json',
      dataType: 'json',
      data: params
    });
    if (status !== 200) throw new Error('ERR_REQUEST');
    if (data.errcode) throw new APIError(data.errcode, data.errmsg);
    return data;
  }

  /**
   * 发送客服消息
   * @author Eric
   * @param  {Object} params 参数
   * @return {Object}        {errcode, errmsg}
   */
  async customerServiceMessageSend(params) {
    let access_token = await this._getToken();
    let URI = `https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=${access_token}`;

    let {status, data} = await urllib.request(URI, {
      method: 'POST',
      contentType: 'json',
      dataType: 'json',
      data: params
    });
    if (status !== 200) throw new Error('ERR_REQUEST');
    if (data.errcode) throw new APIError(data.errcode, data.errmsg);
    return data;
  }
}

module.exports = config => new API(config);
