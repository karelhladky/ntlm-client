"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NtlmClient = void 0;
const fetch_1 = require("./fetch");
const utils_1 = require("./utils");
/**
 * NTLM Client to request protected content over http(s)
 */
class NtlmClient {
    /**
     * Request a url (with Basic or NTLM authentication if required)
     * @param url the http(s) url to request from
     * @param [user] param
     * @param [pwd] param
     * @param [workstation] param
     * @param [domain] param
     * @param [options] object
     * @return response
     */
    request(url, user = '', pwd = '', workstation, domain, options) {
        return __awaiter(this, void 0, void 0, function* () {
            (0, utils_1.log)({ name: 'request' }, options || { debug: url.debug }, 'init request');
            return fetch_1.Fetch.request(setOptions(url, user, pwd, workstation, domain, options));
        });
    }
}
exports.NtlmClient = NtlmClient;
/**
   * Sets the options
   * @param url param
   * @param user param
   * @param pwd param
   * @param [workstation] param
   * @param [domain] param
   * @param [options] param
   * @return the response
   */
function setOptions(url, user, pwd, workstation, domain, options) {
    options = options || {};
    if (typeof url === 'string') {
        options.url = url;
    }
    else {
        options = url;
    }
    options.user = user;
    options.pwd = pwd;
    options.workstation = workstation;
    options.domain = domain;
    options.method = options.method || 'GET';
    options.headers = options.headers || {};
    options.requests = 0;
    NtlmClient.tough = options.tough || NtlmClient.tough;
    if (options.tough) {
        (0, utils_1.log)({ name: 'setOptions' }, options, 'tough-cookie detected, using this cookie jar...');
        NtlmClient.cookie = NtlmClient.tough.Cookie;
        NtlmClient.cookieJar = new NtlmClient.tough.CookieJar();
    }
    options.cookie = NtlmClient.cookie;
    options.cookieJar = NtlmClient.cookieJar;
    (0, utils_1.log)({ name: 'setOptions' }, options, 'options setted!');
    return options;
}
