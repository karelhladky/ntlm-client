import { IOptionsHTTP, IOptionsHTTPS, IResult } from './fetch.interface';
/**
 * Fetch client to request protected content over http(s)
 */
export declare class Fetch {
    /**
     * Requests a NTLM protected http(s) url using options values
     * @param options the Options object
     * @return the response
     */
    static request(options: IOptionsHTTP | IOptionsHTTPS): Promise<IResult>;
    /**
     * Requests a NTLM protected http(s) url using param values
     * @param options the Options object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    private static get;
    /**
     * Follow request redirects
     * @param options the Options object
     * @param result the Result object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    private static executeRedirect;
    /**
     * Sets the Cookie header
     * @param options the Options object
     * @return void
     */
    private static setHeaders;
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
    private static executeNTLM2;
    /**
     * Execute the Basic request creating a authorization header base64 hash using user and pwd
     * @param options the Options object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    private static executeBasic;
    /**
     * Deletes credentials from option object
     * @param options the Options object
     * @return void
     */
    private static deleteCredentials;
    /**
     * Execute the NTLM step 1 request creating the authorization Type1 header message
     * @param options the Options object
     * @param protocol the Protocol object (http or https)
     * @param res the Promise Resolve function
     * @param rej the Promise Reject function
     * @return void
     */
    private static executeNTLM1;
    /**
     * Returns the available server auth methods
     * @param result the Result object
     * @param response the Response object
     * @param options the Options object
     * @return authMethods
     */
    private static getAuthMethods;
    /**
     * Adds the cookie (if one) from header into the jar (if one)
     * @param options the Options object
     * @param response the Response object
     * @return void
     */
    private static setCookie;
    /**
     * Sets the response listeners
     * @param response the Response object
     * @param options the Options object
     * @param result the Result object
     * @param res the Promise Resolve function
     * @return void
     */
    private static setListeners;
}
