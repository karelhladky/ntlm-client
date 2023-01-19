"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Fetch = void 0;
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const fetch_constants_1 = require("./fetch.constants");
const ntlm_1 = require("./ntlm");
const utils_1 = require("./utils");
/**
 * Fetch client to request protected content over http(s)
 */
class Fetch {
    /**
     * Requests a NTLM protected http(s) url using options values
     * @param options the Options object
     * @return the response
     */
    static request(options) {
        (0, utils_1.log)(this, options, 'request init for url: ' + (options === null || options === void 0 ? void 0 : options.url));
        const getProtocol = (url) => (url === null || url === void 0 ? void 0 : url.startsWith('https://')) ? https_1.default : http_1.default;
        const protocol = getProtocol(options.url);
        return new Promise((res, rej) => {
            Fetch.get(options, protocol, res, rej);
        });
    }
    /**
     * Requests a NTLM protected http(s) url using param values
     * @param options the Options object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    static get(options, protocol, res, rej) {
        const result = { body: '', headers: {}, status: 0, options };
        options.requests++;
        (0, utils_1.log)(this, options, `requesting (${options.requests}/${fetch_constants_1.RECURSIVE_LIMIT}) ${options.url}`);
        if (options.requests > fetch_constants_1.RECURSIVE_LIMIT) {
            rej(`recursive request limit (${fetch_constants_1.RECURSIVE_LIMIT}) excedeed!`);
            return;
        }
        try {
            Fetch.setHeaders(options);
            const req = protocol.request(options.url, options, (response) => {
                var _a, _b, _c, _d, _e, _f;
                (0, utils_1.log)(this, options, 'response ' + (response === null || response === void 0 ? void 0 : response.statusCode) + ' from ' + options.url);
                Fetch.setListeners(response, options, result, res);
                Fetch.setCookie(options, response);
                const authMethods = Fetch.getAuthMethods(result, response, options);
                if (result.status === 401 &&
                    options.user && options.pwd &&
                    (authMethods === null || authMethods === void 0 ? void 0 : authMethods.indexOf('ntlm')) !== -1 &&
                    !((_a = options.authMethod) === null || _a === void 0 ? void 0 : _a.includes('ntlm'))) {
                    Fetch.executeNTLM1(options, protocol, res, rej);
                }
                else if (result.status === 401 &&
                    options.user && options.pwd &&
                    (authMethods === null || authMethods === void 0 ? void 0 : authMethods.indexOf('basic')) !== -1 &&
                    !((_b = options.authMethod) === null || _b === void 0 ? void 0 : _b.includes('basic'))) {
                    Fetch.executeBasic(options, protocol, res, rej);
                }
                else if (result.status > 399 && result.status < 500 &&
                    options.user && options.pwd &&
                    ((_c = options.headers) === null || _c === void 0 ? void 0 : _c['Authorization']) &&
                    ((_d = options.authMethod) === null || _d === void 0 ? void 0 : _d.includes('ntlm'))) {
                    Fetch.executeNTLM2(result, options, response, protocol, res, rej);
                }
                else if (((_e = result.headers) === null || _e === void 0 ? void 0 : _e['Location']) &&
                    result.status > 300 &&
                    result.status < 310 &&
                    !options.disableRedirect) {
                    Fetch.executeRedirect(options, result, protocol, res, rej);
                }
                else {
                    (_f = options.agent) === null || _f === void 0 ? void 0 : _f.destroy();
                    (0, utils_1.log)(this, options, 'this request can be resolved');
                    result.resolve = true;
                }
            });
            req.on('error', (err) => {
                (0, utils_1.log)(this, options, 'error on request!');
                rej(err);
            });
            if (options.body) {
                req.write(options.body);
            }
            req.end();
        }
        catch (error) {
            (0, utils_1.log)(this, options, 'error on try!');
            rej(error);
        }
    }
    /**
     * Follow request redirects
     * @param options the Options object
     * @param result the Result object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    static executeRedirect(options, result, protocol, res, rej) {
        const getUrl = () => {
            var _a;
            const to = result.headers['Location'];
            if (to.startsWith('http:') || to.startsWith('https:')) {
                return to;
            }
            const url = new URL(options.url);
            if (to.startsWith('/')) {
                return url.origin + to;
            }
            const parts = (_a = options.url) === null || _a === void 0 ? void 0 : _a.split('/');
            const sanitized = parts === null || parts === void 0 ? void 0 : parts.slice(0, parts.length - 1);
            return sanitized === null || sanitized === void 0 ? void 0 : sanitized.join('/').concat('/').concat(to);
        };
        (0, utils_1.log)(this, options, result.status + ' Location/Redirect ' + options.url + ' -> ' + result.headers['Location']);
        if (result.status === 301) {
            (0, utils_1.log)(this, options, 'setting request method to GET (301 status code requeriment)');
            options.method = 'GET';
        }
        options.url = getUrl();
        Fetch.get(options, protocol, res, rej);
    }
    /**
     * Sets the Cookie header
     * @param options the Options object
     * @return void
     */
    static setHeaders(options) {
        options.headers = options.headers || {};
        options.authMethod = options.authMethod || [];
        if (options.cookieJar) {
            options.headers.cookie =
                options.cookieJar.getCookiesSync(options.url).map((c) => c.cookieString()).join('; ');
        }
        (0, utils_1.log)({ name: 'setHeaders' }, options, 'headers = ' + JSON.stringify(options.headers));
    }
    /**
     * Execute the NTLM step 2 request by decoding the server response and creating the new message authorization header
     * @param result the Result object
     * @param options the Options object
     * @param response the Response object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    static executeNTLM2(result, options, response, protocol, res, rej) {
        options.headers = options.headers || {};
        const t2m = (0, ntlm_1.decodeType2Message)(result.headers['www-authenticate']);
        (0, utils_1.log)(this, options, 'NTLM Step 2 = ' + JSON.stringify(t2m));
        const authHeader = (0, ntlm_1.createType3Message)(t2m, (options === null || options === void 0 ? void 0 : options.user) || '', (options === null || options === void 0 ? void 0 : options.pwd) || '', options === null || options === void 0 ? void 0 : options.workstation, options === null || options === void 0 ? void 0 : options.domain);
        options.headers['Authorization'] = authHeader;
        Fetch.deleteCredentials(options);
        response.resume();
        Fetch.get(options, protocol, res, rej);
    }
    /**
     * Execute the Basic request creating a authorization header base64 hash using user and pwd
     * @param options the Options object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    static executeBasic(options, protocol, res, rej) {
        var _a;
        (_a = options.authMethod) === null || _a === void 0 ? void 0 : _a.push('basic');
        options.headers = options.headers || {};
        options.headers['Authorization'] = (0, ntlm_1.createBasicMessage)((options === null || options === void 0 ? void 0 : options.user) || '', (options === null || options === void 0 ? void 0 : options.pwd) || '');
        Fetch.deleteCredentials(options);
        Fetch.get(options, protocol, res, rej);
    }
    /**
     * Deletes credentials from option object
     * @param options the Options object
     * @return void
     */
    static deleteCredentials(options) {
        delete options.user;
        delete options.pwd;
        delete options.workstation;
        delete options.domain;
    }
    /**
     * Execute the NTLM step 1 request creating the authorization Type1 header message
     * @param options the Options object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    static executeNTLM1(options, protocol, res, rej) {
        var _a;
        options.headers = options.headers || {};
        (_a = options.authMethod) === null || _a === void 0 ? void 0 : _a.push('ntlm');
        (0, utils_1.log)(this, options, 'NTLM Step 1 (ntlm authenticate method allowed)');
        options.agent = options.agent || new protocol.Agent({ keepAlive: true, maxSockets: 1 });
        options.headers['Authorization'] = (0, ntlm_1.createType1Message)(options.workstation, options.domain);
        (0, utils_1.log)(this, options, 'Authorization header = ' + options.headers['Authorization']);
        Fetch.get(options, protocol, res, rej);
    }
    /**
     * Returns the available server auth methods
     * @param result the Result object
     * @param response the Response object
     * @param options the Options object
     * @return authMethods
     */
    static getAuthMethods(result, response, options) {
        var _a, _b, _c;
        result.resolve = false;
        result.status = response.statusCode || 0;
        result.headers = response.headers;
        (0, utils_1.log)(this, options, 'www-authenticate header = ' + ((_a = response.headers) === null || _a === void 0 ? void 0 : _a['www-authenticate']));
        return (_c = (_b = response.headers) === null || _b === void 0 ? void 0 : _b['www-authenticate']) === null || _c === void 0 ? void 0 : _c.split(',').map((i) => i.trim().toLowerCase());
    }
    /**
     * Adds the cookie (if one) from header into the jar (if one)
     * @param options the Options object
     * @param response the Response object
     * @return void
     */
    static setCookie(options, response) {
        if (options.cookieJar && options.cookie) {
            const cookiesHeader = response.headers['set-cookie'] || [];
            cookiesHeader.forEach((cookie) => {
                (0, utils_1.log)(this, options, 'setting cookie');
                options.cookieJar.setCookieSync(options.cookie.parse(cookie), options.url);
            });
        }
    }
    /**
     * Sets the response listeners
     * @param response the Response object
     * @param options the Options object
     * @param result the Result object
     * @param res the Promise Resolve function
     * @return void
     */
    static setListeners(response, options, result, res) {
        response.on('data', (data) => {
            (0, utils_1.log)(this, options, 'data received ' + data.length + ' bytes chunk');
            result.body += data;
        });
        response.on('close', () => {
            if (result.resolve) {
                (0, utils_1.log)(this, options, 'resolve with ' + result.status);
                delete result.resolve;
                res(result);
            }
        });
        response.on('end', () => {
            if (result.resolve) {
                (0, utils_1.log)(this, options, 'resolve with ' + result.status);
                delete result.resolve;
                res(result);
            }
        });
    }
}
exports.Fetch = Fetch;
