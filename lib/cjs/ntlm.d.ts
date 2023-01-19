import { IType2 } from './fetch.interface';
/**
 * Returns the basic auth header
 * @param user the username
 * @param pwd the password
 * @return the basic auth header
 */
export declare function createBasicMessage(user: string, pwd: string): string;
/**
 * Returns the type1 NTLM token
 * @param workstation param
 * @param target param
 * @return the NTLM type1 token
 */
export declare function createType1Message(workstation?: string | undefined, target?: string | undefined): string;
/**
 * Returns decoded type2 message
 * @param str param
 * @return decoded object
 */
export declare function decodeType2Message(str: any): IType2;
/**
 * Returns type3 NTLM token
 * @param type2Message param
 * @param username param
 * @param password param
 * @param [workstation] param
 * @param [target] param
 * @return NTLM type3 token
 */
export declare function createType3Message(type2Message: IType2, username: string, password: string, workstation?: string, target?: string): string;
