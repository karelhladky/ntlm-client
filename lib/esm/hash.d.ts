/// <reference types="node" />
/**
 * Generates a LM response
 * @param challenge the challenge
 * @param lmhash the lm hash
 * @return the LM response
 */
export declare function createLMResponse(challenge: any, lmhash: any): Buffer;
/**
 * Generates a LM hash password response
 * @param password the Password to hash
 * @return the LM Hash password
 */
export declare function createLMHash(password: string): Buffer;
/**
 * Geberates a NTLM response
 * @param challenge param
 * @param ntlmhash param
 * @return the response
 */
export declare function createNTLMResponse(challenge: any, ntlmhash: any): Buffer;
/**
 * Generates de digest hash for password
 * @param password param
 * @return the response
 */
export declare function createNTLMHash(password: string): Buffer;
/**
 * Generates a NTLM v2 digest hash
 * @param ntlmhash param
 * @param username param
 * @param authTargetName param
 * @return the response
 */
export declare function createNTLMv2Hash(ntlmhash: any, username: string, authTargetName: string | undefined): Buffer;
/**
 * Generates a LM v2 response
 * @param type2message param
 * @param username param
 * @param ntlmhash param
 * @param nonce param
 * @param targetName param
 * @return the response
 */
export declare function createLMv2Response(type2message: any, username: string, ntlmhash: any, nonce: string, targetName: string): Buffer;
/**
 * Generates a NTLM v2 response
 * @param type2message param
 * @param username param
 * @param ntlmhash param
 * @param nonce param
 * @param targetName param
 * @return the response
 */
export declare function createNTLMv2Response(type2message: any, username: string, ntlmhash: any, nonce: string, targetName: string): Buffer;
/**
 * Generrates a random string with requested length
 * @param {number} length the length of the requested random string
 * @return {string} the random string
 */
export declare function createPseudoRandomValue(length: number): string;
