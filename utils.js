const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');
const elliptic = require('elliptic');
const NodeRSA = require('node-rsa');

const USER_PRESENTED = 0x01;
const USER_VERIFIED = 0x04;

const COSEKEYS = {
    'kty': 1,
    'alg': 3,
    'crv': -1,
    'x': -2,
    'y': -3,
    'n': -1,
    'e': -2
}

const COSEKTY = {
    'OKP': 1,
    'EC2': 2,
    'RSA': 3
}

const COSERSASCHEME = {
    '-3': 'pss-sha256',
    '-39': 'pss-sha512',
    '-38': 'pss-sha384',
    '-65535': 'pkcs1-sha1',
    '-257': 'pkcs1-sha256',
    '-258': 'pkcs1-sha384',
    '-259': 'pkcs1-sha512'
}

const COSECRV = {
    '1': 'p256',
    '2': 'p384',
    '3': 'p521'
}

const COSEALGHASH = {
    '-257': 'sha256',
    '-258': 'sha384',
    '-259': 'sha512',
    '-65535': 'sha1',
    '-39': 'sha512',
    '-38': 'sha384',
    '-37': 'sha256',
    '-260': 'sha256',
    '-261': 'sha512',
    '-7': 'sha256',
    '-36': 'sha384',
    '-37': 'sha512'
}

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
let verifySignature = (signature, data, publicKey) => {
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}

let base64ToPem = (b64cert) => {
    let pemcert = '';
    for (let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + '\n';

    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
}

let base64UrlChecker = (b64UrlString) => {
    if (b64UrlString.indexOf('+') !== -1) {
        return false
    } else if (b64UrlString.indexOf('/') !== -1) {
        return false;
    } else if (b64UrlString.indexOf('=') !== -1) {
        return false;
    }
    return true;
}

let userVerificationChecker = (flags, userVerification) => {
    switch (userVerification) {
        case 'required':
            if (!(flags & USER_VERIFIED))
                throw new Error('User was NOT verified durring authentication!');

            break;

        case 'preferred':
            break;

        case 'discouraged':
            break;
        default:
            break;
    }
    return;
}

var getCertificateInfo = (certificate) => {
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(certificate);

    let subjectString = subjectCert.getSubjectString();
    let subjectParts = subjectString.slice(1).split('/');

    let subject = {};
    for (let field of subjectParts) {
        let kv = field.split('=');
        subject[kv[0]] = kv[1];
    }

    let version = subjectCert.version;
    let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

    return {
        subject, version, basicConstraintsCA
    }
}


/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
    len = len || 32;

    let buff = crypto.randomBytes(len);

    return base64url(buff);
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @param  {String} attestation    - attestation
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
let generateServerMakeCredRequest = (username, displayName, id, attestation) => {
    return {
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "56 Corporation"
        },

        user: {
            id: id,
            name: username,
            displayName: displayName
        },

        attestation: attestation || 'direct',

        pubKeyCredParams: [
            {
                type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
            }
        ]
    }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (authenticators) => {
    let allowCredentials = [];
    for (let authr of authenticators) {
        allowCredentials.push({
            type: 'public-key',
            id: authr.credID,
        })
    }
    return {
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials
    }
}

let hash = (alg, data) => {
    return crypto.createHash(alg).update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x = coseStruct.get(-2);
    let y = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */

        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

    return PEMKey
}

var parseAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    let flagsInt = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt
    }

    let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    let aaguid = undefined;
    let credID = undefined;
    let COSEPublicKey = undefined;

    if (flags.at) {
        aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
        let credIDLen = credIDLenBuf.readUInt16BE(0);
        credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
        COSEPublicKey = buffer;
    }

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseMakeCredAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);
    let aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    let credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, credIDLenBuf, COSEPublicKey }
}

let verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];

    let response = { 'verified': false };
    if (ctapMakeCredResp.fmt === 'none') {
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
        if (ctapMakeCredResp.attStmt.x5c)
            throw new Error('Send attestation FULL packed with fmt set none.');

        if (!(authrDataStruct.flags & USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        response.verified = true;
        if (response.verified) {
            response.authrInfo = {
                fmt: 'none',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (ctapMakeCredResp.fmt === 'fido-u2f') {
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        if (!(authrDataStruct.flags & USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        if (Number(authrDataStruct.aaguid.toString('hex')) !== 0)
            throw new Error('authData.AAGUID is not 0x00');

        let clientDataHash = hash('SHA256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let reservedByte = Buffer.from([0x00]);
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature = ctapMakeCredResp.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (ctapMakeCredResp.fmt === 'packed') {
        response = verifyPackedAttestation(webAuthnResponse);
    }

    return response
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
    for (let authr of authenticators) {
        if (authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    return { rpIdHash, flagsBuf, flags, counter, counterBuf }
}

let verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators, userVerification) => {
    let authr = findAuthr(webAuthnResponse.id, authenticators);

    if (!base64UrlChecker(webAuthnResponse.response.authenticatorData))
        throw new Error('AuthenticatorData is not base64url encoded');

    if (webAuthnResponse.response.userHandle && typeof webAuthnResponse.response.userHandle !== 'string')
        throw new Error('userHandle is not of type DOMString');

    if (!base64UrlChecker(webAuthnResponse.response.signature))
        throw new Error('Signature is not base64url encoded');

    let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData)

    let response = { 'verified': false }
    let authrDataStruct = parseGetAssertAuthData(authenticatorData)
    userVerificationChecker(authrDataStruct.flags, userVerification);

    let clientDataHash = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
    let signatureBase = Buffer.concat([authenticatorData, clientDataHash])
    let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey))
    let signature = base64url.toBuffer(webAuthnResponse.response.signature)
    response.verified = verifySignature(signature, signatureBase, publicKey)

    if (response.verified) {
        if (authrDataStruct.counter <= authr.counter) { throw new Error('Authr counter did not increase!') }

        authr.counter = authrDataStruct.counter
    }

    return response

}

let verifyPackedAttestation = (webAuthnResponse) => {
    let response = { 'verified': false };
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
    let authDataStruct = parseAuthData(attestationStruct.authData);

    if (!authDataStruct.flags.up)
        throw new Error('User was NOT presented durring authentication!');
    userVerificationChecker(authDataStruct.flags)

    if (!attestationStruct.attStmt.alg)
        throw new Error('attStmt.alg is missing');

    if (!COSEALGHASH.hasOwnProperty(attestationStruct.attStmt.alg))
        throw new Error('attStmt.alg is not support.')

    if (typeof attestationStruct.attStmt.alg !== 'number')
        throw new Error('attStmt.alg is Not a Number');

    let clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);

    let signatureBuffer = attestationStruct.attStmt.sig;
    let publicKey = undefined;

    if (attestationStruct.attStmt.x5c) {
        /* ----- Verify FULL attestation ----- */
        publicKey = base64url.encode(COSEECDHAtoPKCS(authDataStruct.COSEPublicKey));
        let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
        let certInfo = getCertificateInfo(leafCert);

        if (certInfo.subject.OU !== 'Authenticator Attestation')
            throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

        if (!certInfo.subject.CN)
            throw new Error('Batch certificate CN MUST no be empty!');

        if (!certInfo.subject.O)
            throw new Error('Batch certificate CN MUST no be empty!');

        if (!certInfo.subject.C || certInfo.subject.C.length !== 2)
            throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');

        if (certInfo.basicConstraintsCA)
            throw new Error('Batch certificate basic constraints CA MUST be false!');

        if (certInfo.version !== 3)
            throw new Error('Batch certificate version MUST be 3(ASN1 2)!');

        response.verified = crypto.createVerify('sha256')
            .update(signatureBaseBuffer)
            .verify(leafCert, signatureBuffer);
        /* ----- Verify FULL attestation ENDS ----- */
    } else if (attestationStruct.attStmt.ecdaaKeyId) {
        throw new Error('ECDAA IS NOT SUPPORTED YET!');
    } else {
        /* ----- Verify SURROGATE attestation ----- */
        let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
        let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
        if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
            let x = pubKeyCose.get(COSEKEYS.x);
            let y = pubKeyCose.get(COSEKEYS.y);
            let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);
            let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);
            let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
            let key = ec.keyFromPublic(ansiKey);
            publicKey = base64url.encode(ansiKey);
            response.verified = key.verify(signatureBaseHash, signatureBuffer)
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
            let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];
            let key = new NodeRSA(undefined, { signingScheme });
            key.importKey({
                n: pubKeyCose.get(COSEKEYS.n),
                e: 65537,
            }, 'components-public');
            response.verified = key.verify(signatureBaseBuffer, signatureBuffer)
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
            let x = pubKeyCose.get(COSEKEYS.x);
            let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

            let key = new elliptic.eddsa('ed25519');
            key.keyFromPublic(x)
            publicKey = key;
            response.verified = key.verify(signatureBaseHash, signatureBuffer)
        }
        /* ----- Verify SURROGATE attestation ENDS ----- */
    }

    if (response.verified) {
        response.authrInfo = {
            fmt: 'packed',
            publicKey: publicKey,
            counter: authDataStruct.counter,
            credID: base64url.encode(authDataStruct.credID),
        }
    } else {
        throw new Error('Failed to verify the signature!');
    }

    return response;
}


module.exports = {
    base64UrlChecker,
    randomBase64URLBuffer,
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse
}
