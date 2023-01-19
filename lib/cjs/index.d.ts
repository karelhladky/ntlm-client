import { IOptionsHTTP, IOptionsHTTPS, IResult } from './fetch.interface';
/**
 * NTLM Client to request protected content over http(s)
 */
export declare class NtlmClient {
    static tough: any;
    static cookie: any;
    static cookieJar: any;
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
    request(url: string | IOptionsHTTP | IOptionsHTTPS, user?: string, pwd?: string, workstation?: string, domain?: string, options?: IOptionsHTTP | IOptionsHTTPS): Promise<IResult>;
}
