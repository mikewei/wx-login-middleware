import sha1 from './sha1';

function wxLogin() {
    return new Promise((resolve, reject) => {
        wx.login({
            success(res) {
                if (res.code) resolve(res);
                else reject(res);
            },
            fail: reject
        });
    });
}

function wxRequest(params) {
    return new Promise((resolve, reject) => {
        wx.request({
            success(res) {
                if (res.statusCode >= 200 && res.statusCode < 300) resolve(res);
                else reject(res);
            },
            fail: reject,
            ...params
        });
    });
}

function getSigUrl(url) {
    if (url.startsWith('http://')) {
        url = url.substring(7);
    } else if (url.startsWith('https://')) {
        url = url.substring(8);
    }
    let pos = url.indexOf('/');
    if (pos === -1) {
        return '/';
    } else {
        return url.substring(pos);
    }
}

const base_url = 'http://localhost:8080'

export const api = {
    appid: wx.getAccountInfoSync().miniProgram.appId,
    loginState: null,
    nonce: Math.floor(Math.random() * 65536 * 32768),
    // login
    async login() {
        let code;
        try {
            const res = await wxLogin();
            console.log('wx login ok: ', res);
            code = res.code;
        } catch (err) {
            console.error('wx login err: ', err);
            throw err;
        }
        try {
            const res = await wxRequest({
                url: base_url + '/login',
                method: "POST",
                data: {
                    appid: this.appid,
                    code: code
                }
            });
            console.log('api login ok: ', res);
            this.loginState = res.data;
            return res;
        } catch (err) {
            console.error('api login err: ', err);
            throw err;
        }
    },
    // request
    async request(params) {
        if (params.url.startsWith('/')) {
            params.url = base_url + params.url;
        }
        let sig_url = getSigUrl(params.url);
        if (!('header' in params)) {
            params.header = {};
        }
        if (this.loginState && !('WX-LOGIN-STOKEN' in params.header)) {
            params.header['WX-LOGIN-STOKEN'] = this.loginState.stoken;
        }
        if (this.loginState && !('WX-LOGIN-SIG' in params.header)) {
            let ts = Date.now();
            let nc = this.nonce++;
            let ts_nc_str = ':' + ts + ':' + nc + ':';
            params.header['WX-LOGIN-SIG'] = 'SG1' + ts_nc_str + sha1(sig_url + ts_nc_str + this.loginState.skey);
        }
        console.log('req params:', params, sig_url);
        return await wxRequest(params);
    },

}  // api

export default api;