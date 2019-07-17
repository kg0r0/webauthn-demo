const base64url = require('base64url');
const utils = require('./utils');

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
const generateServerGetAssertion = (authenticators) => {
    let allowCredentials = [];
    for (let authr of authenticators) {
        allowCredentials.push({
            type: 'public-key',
            id: authr.credID,
        })
    }
    return {
        challenge: utils.randomBase64URLBuffer(32),
        allowCredentials: allowCredentials
    }
}


/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
const findAuthr = (credID, authenticators) => {
    for (let authr of authenticators) {
        if (authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Tries to verify AuthenticatorAssertionResponse
 * @param  {Object} webAuthnResponse 
 * @param  {Array} authenticators
 * @param  {String} userVerification
 * @return {Object}                   - verification result  
 */
const verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators, userVerification) => {
    const authr = findAuthr(webAuthnResponse.body.id, authenticators);

    if (!utils.isBase64UrlEncoded(webAuthnResponse.body.response.authenticatorData))
        throw new Error('AuthenticatorData is not base64url encoded');

    if (webAuthnResponse.body.response.userHandle && typeof webAuthnResponse.body.response.userHandle !== 'string')
        throw new Error('userHandle is not of type DOMString');

    if (!utils.isBase64UrlEncoded(webAuthnResponse.body.response.signature))
        throw new Error('Signature is not base64url encoded');

    const authenticatorData = base64url.toBuffer(webAuthnResponse.body.response.authenticatorData);

    let response = { 'verified': false }
    const authrDataStruct = utils.parseAuthData(authenticatorData);

    if (Buffer.compare(authrDataStruct.rpIdHash, utils.hash('sha256', Buffer.from(webAuthnResponse.hostname))) !== 0)
        throw new Error('rpIdHash don\'t match!')

    utils.verifyUserVerification(authrDataStruct.flags, userVerification);

    const clientDataHash = utils.hash('sha256', base64url.toBuffer(webAuthnResponse.body.response.clientDataJSON));
    const signatureBase = Buffer.concat([authenticatorData, clientDataHash]);
    const publicKey = utils.ASN1toPEM(base64url.toBuffer(authr.publicKey));
    const signature = base64url.toBuffer(webAuthnResponse.body.response.signature);
    response.verified = utils.verifySignature(signature, signatureBase, publicKey);

    if (response.verified) {
        if (authrDataStruct.counter !== 0 && authr.counter !== 0 && authrDataStruct.counter <= authr.counter) { throw new Error('Authr counter did not increase!') }

        authr.counter = authrDataStruct.counter;
    }

    return response

}


module.exports = {
    generateServerGetAssertion,
    verifyAuthenticatorAssertionResponse
}
