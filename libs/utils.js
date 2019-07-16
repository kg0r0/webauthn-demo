const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');
const elliptic = require('elliptic');
const NodeRSA = require('node-rsa');
const ldap2date = require('ldap2date');

const gsr2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==';

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

const TPM_ALG = {
    0x0000: "TPM_ALG_ERROR",
    0x0001: "TPM_ALG_RSA",
    0x0004: "TPM_ALG_SHA",
    0x0004: "TPM_ALG_SHA1",
    0x0005: "TPM_ALG_HMAC",
    0x0006: "TPM_ALG_AES",
    0x0007: "TPM_ALG_MGF1",
    0x0008: "TPM_ALG_KEYEDHASH",
    0x000A: "TPM_ALG_XOR",
    0x000B: "TPM_ALG_SHA256",
    0x000C: "TPM_ALG_SHA384",
    0x000D: "TPM_ALG_SHA512",
    0x0010: "TPM_ALG_NULL",
    0x0012: "TPM_ALG_SM3_256",
    0x0013: "TPM_ALG_SM4",
    0x0014: "TPM_ALG_RSASSA",
    0x0015: "TPM_ALG_RSAES",
    0x0016: "TPM_ALG_RSAPSS",
    0x0017: "TPM_ALG_OAEP",
    0x0018: "TPM_ALG_ECDSA",
    0x0019: "TPM_ALG_ECDH",
    0x001A: "TPM_ALG_ECDAA",
    0x001B: "TPM_ALG_SM2",
    0x001C: "TPM_ALG_ECSCHNORR",
    0x001D: "TPM_ALG_ECMQV",
    0x0020: "TPM_ALG_KDF1_SP800_56A",
    0x0021: "TPM_ALG_KDF2",
    0x0022: "TPM_ALG_KDF1_SP800_108",
    0x0023: "TPM_ALG_ECC",
    0x0025: "TPM_ALG_SYMCIPHER",
    0x0026: "TPM_ALG_CAMELLIA",
    0x0040: "TPM_ALG_CTR",
    0x0041: "TPM_ALG_OFB",
    0x0042: "TPM_ALG_CBC",
    0x0043: "TPM_ALG_CFB",
    0x0044: "TPM_ALG_ECB"
}

const TPM_ST = {
    0x00C4: "TPM_ST_RSP_COMMAND",
    0X8000: "TPM_ST_NULL",
    0x8001: "TPM_ST_NO_SESSIONS",
    0x8002: "TPM_ST_SESSIONS",
    0x8014: "TPM_ST_ATTEST_NV",
    0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT",
    0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
    0x8017: "TPM_ST_ATTEST_CERTIFY",
    0x8018: "TPM_ST_ATTEST_QUOTE",
    0x8019: "TPM_ST_ATTEST_TIME",
    0x801A: "TPM_ST_ATTEST_CREATION",
    0x8021: "TPM_ST_CREATION",
    0x8022: "TPM_ST_VERIFIED",
    0x8023: "TPM_ST_AUTH_SECRET",
    0x8024: "TPM_ST_HASHCHECK",
    0x8025: "TPM_ST_AUTH_SIGNED",
    0x8029: "TPM_ST_FU_MANIFEST"
}

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
const verifySignature = (signature, data, publicKey) => {
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}

const base64ToPem = (b64cert) => {
    let pemcert = '';
    for (let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + '\n';

    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
}

/**
 * Takes string and tries to verify base64 url encoded. 
 * @param  {String} b64UrlString 
 * @return {Boolean}
 */
const verifyBase64Url = (b64UrlString) => {
    if (b64UrlString.indexOf('+') !== -1) {
        return false
    } else if (b64UrlString.indexOf('/') !== -1) {
        return false;
    } else if (b64UrlString.indexOf('=') !== -1) {
        return false;
    }
    return true;
}

const verifyUserVerification = (flags, userVerification) => {
    switch (userVerification) {
        case 'required':
            if (!flags.uv)
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

const verifyRootCert = (certificate) => {
    const rootPem = certificate;
    const rootCert = new jsrsasign.X509();
    rootCert.readCertPEM(rootPem);
    if (rootCert.getIssuerString() == rootCert.getSubjectString()) {
        return true;
    }
    return false;
}

const validateCertificatePath = (certificates) => {
    if (verifyRootCert(certificates[certificates.length - 1]))
        throw new Error('x5c contains full chain!')

    if ((new Set(certificates)).size !== certificates.length)
        throw new Error('Failed to validate certificates path! Dublicate certificates detected!')

    for (let i = 0; i < certificates.length - 1; i++) {
        const subjectPem = certificates[i];
        const subjectCert = new jsrsasign.X509();
        subjectCert.readCertPEM(subjectPem);

        const issuerPem = certificates[i + 1];
        const issuerCert = new jsrsasign.X509();
        issuerCert.readCertPEM(issuerPem);
        const notbefore = ldap2date.parse('20' + issuerCert.getNotBefore()).getTime();
        const notafter = ldap2date.parse('20' + issuerCert.getNotAfter()).getTime();
        const now = new Date().getTime();
        if (now < notbefore)
            throw new Error('Leaf certificate is not yet started!')

        if (notafter < now)
            throw new Error('Leaf certificate is expired!')

        if (subjectCert.getIssuerString() !== issuerCert.getSubjectString())
            throw new Error(`Failed to validate certificate path! Issuers dont match!`)

        const subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
        const algorithm = subjectCert.getSignatureAlgorithmField();
        const signatureHex = subjectCert.getSignatureValueHex();

        const Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
        Signature.init(issuerPem);
        Signature.updateHex(subjectCertStruct);

        if (!Signature.verify(signatureHex))
            throw new Error('Failed to validate certificate path!')

    }

    return true
}

const getCertificateInfo = (certificate) => {
    const subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(certificate);
    const notbefore = ldap2date.parse('20' + subjectCert.getNotBefore()).getTime();
    const notafter = ldap2date.parse('20' + subjectCert.getNotAfter()).getTime();
    const now = new Date().getTime();

    if (now < notbefore)
        throw new Error('Leaf certificate is not yet started!')

    if (notafter < now)
        throw new Error('Leaf certificate is expired!')

    const subjectString = subjectCert.getSubjectString();
    const subjectParts = subjectString.slice(1).split('/');

    let subject = {};
    for (let field of subjectParts) {
        let kv = field.split('=');
        subject[kv[0]] = kv[1];
    }

    const version = subjectCert.version;
    const basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

    return {
        subject, version, basicConstraintsCA
    }
}

const parsePubArea = (pubAreaBuffer) => {
    const typeBuffer = pubAreaBuffer.slice(0, 2);
    const type = TPM_ALG[typeBuffer.readUInt16BE(0)];
    pubAreaBuffer = pubAreaBuffer.slice(2);

    const nameAlgBuffer = pubAreaBuffer.slice(0, 2)
    const nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];
    pubAreaBuffer = pubAreaBuffer.slice(2);

    const objectAttributesBuffer = pubAreaBuffer.slice(0, 4);
    const objectAttributesInt = objectAttributesBuffer.readUInt32BE(0);
    const objectAttributes = {
        fixedTPM: !!(objectAttributesInt & 1),
        stClear: !!(objectAttributesInt & 2),
        fixedParent: !!(objectAttributesInt & 8),
        sensitiveDataOrigin: !!(objectAttributesInt & 16),
        userWithAuth: !!(objectAttributesInt & 32),
        adminWithPolicy: !!(objectAttributesInt & 64),
        noDA: !!(objectAttributesInt & 512),
        encryptedDuplication: !!(objectAttributesInt & 1024),
        restricted: !!(objectAttributesInt & 32768),
        decrypt: !!(objectAttributesInt & 65536),
        signORencrypt: !!(objectAttributesInt & 131072)
    }
    pubAreaBuffer = pubAreaBuffer.slice(4);

    const authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
    pubAreaBuffer = pubAreaBuffer.slice(2);
    const authPolicy = pubAreaBuffer.slice(0, authPolicyLength);
    pubAreaBuffer = pubAreaBuffer.slice(authPolicyLength);

    let parameters = undefined;
    if (type === 'TPM_ALG_RSA') {
        parameters = {
            symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
            scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
            keyBits: pubAreaBuffer.slice(4, 6).readUInt16BE(0),
            exponent: pubAreaBuffer.slice(6, 10).readUInt32BE(0)
        }
        pubAreaBuffer = pubAreaBuffer.slice(10);
    } else if (type === 'TPM_ALG_ECC') {
        parameters = {
            symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
            scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
            curveID: TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
            kdf: TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)]
        }
        pubAreaBuffer = pubAreaBuffer.slice(8);
    } else
        throw new Error(type + ' is an unsupported type!');

    const uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
    pubAreaBuffer = pubAreaBuffer.slice(2);
    const unique = pubAreaBuffer.slice(0, uniqueLength);
    pubAreaBuffer = pubAreaBuffer.slice(uniqueLength);

    return {
        type,
        nameAlg,
        objectAttributes,
        authPolicy,
        parameters,
        unique
    }
}

const parseCertInfo = (certInfoBuffer) => {
    const magicBuffer = certInfoBuffer.slice(0, 4);
    const magic = magicBuffer.readUInt32BE(0);
    certInfoBuffer = certInfoBuffer.slice(4);

    const typeBuffer = certInfoBuffer.slice(0, 2);
    const type = TPM_ST[typeBuffer.readUInt16BE(0)];
    certInfoBuffer = certInfoBuffer.slice(2);

    const qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    certInfoBuffer  = certInfoBuffer.slice(2);
    const qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength);
    certInfoBuffer  = certInfoBuffer.slice(qualifiedSignerLength);

    const extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
    certInfoBuffer  = certInfoBuffer.slice(2);
    const extraData   = certInfoBuffer.slice(0, extraDataLength);
    certInfoBuffer  = certInfoBuffer.slice(extraDataLength);

    const clockInfo = {
        clock: certInfoBuffer.slice(0, 8),
        resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
        restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
        safe: !!(certInfoBuffer[16])
    }
    certInfoBuffer  = certInfoBuffer.slice(17);

    let firmwareVersion = certInfoBuffer.slice(0, 8);
    certInfoBuffer      = certInfoBuffer.slice(8);

    const attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
    const attestedNameBuffer = certInfoBuffer.slice(2, attestedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength)

    const attestedQualifiedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
    const attestedQualifiedNameBuffer = certInfoBuffer.slice(2, attestedQualifiedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength)

    const attested = {
        nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
        name: attestedNameBuffer,
        qualifiedName: attestedQualifiedNameBuffer
    }

    return {
        magic,
        type,
        qualifiedSigner,
        extraData,
        clockInfo,
        firmwareVersion,
        attested
    }
}

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
const randomBase64URLBuffer = (len) => {
    len = len || 32;

    const buff = crypto.randomBytes(len);

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
const generateServerMakeCredRequest = (username, displayName, id, attestation) => {
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
const generateServerGetAssertion = (authenticators) => {
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

/**
 * Generates hashed data
 * @param  {String} alg 
 * @param  {String} data 
 * @return {Boolean}
 */
const hash = (alg, data) => {
    return crypto.createHash(alg).update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
const COSEECDHAtoPKCS = (COSEPublicKey) => {
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

    const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    const tag = Buffer.from([0x04]);
    const x = coseStruct.get(-2);
    const y = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
const ASN1toPEM = (pkBuffer) => {
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

    const b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

    return PEMKey
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
const parseAuthData = (buffer) => {
    const rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    const flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    const flagsInt = flagsBuf[0];
    const flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt
    }

    const counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    const counter = counterBuf.readUInt32BE(0);

    let aaguid = undefined;
    let credID = undefined;
    let credIDLenBuf = undefined;
    let COSEPublicKey = undefined;

    if (flags.at) {
        aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
        credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
        const credIDLen = credIDLenBuf.readUInt16BE(0);
        credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
        COSEPublicKey = buffer;
    }

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, credIDLenBuf, COSEPublicKey }
}

/**
 * Tries to verify AuthenticatorAttestationResponse
 * @param  {Object} webAuthnResponse 
 * @return {Object}                   - verification result  
 */
const verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

    let response = { 'verified': false };
    if (attestationStruct.fmt === 'none') {
        const authrDataStruct = parseAuthData(attestationStruct.authData);
        if (attestationStruct.attStmt.x5c)
            throw new Error('Send attestation FULL packed with fmt set none.');

        if (!authrDataStruct.flags.up)
            throw new Error('User was NOT presented durring authentication!');

        const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        response.verified = true;
        if (response.verified) {
            response.authrInfo = {
                fmt: 'none',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (attestationStruct.fmt === 'fido-u2f') {
        const authrDataStruct = parseAuthData(attestationStruct.authData);

        if (!(authrDataStruct.flags.up))
            throw new Error('User was NOT presented durring authentication!');

        if (Number(authrDataStruct.aaguid.toString('hex')) !== 0)
            throw new Error('authData.AAGUID is not 0x00');

        const clientDataHash = hash('SHA256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        const reservedByte = Buffer.from([0x00]);
        const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
        const signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        const PEMCertificate = ASN1toPEM(attestationStruct.attStmt.x5c[0]);
        const signature = attestationStruct.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate);

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (attestationStruct.fmt === 'packed') {
        response = verifyPackedAttestation(webAuthnResponse);
    } else if (attestationStruct.fmt === 'tpm') {
        if (attestationStruct.attStmt.ver !== '2.0')
            throw new Error('ver is not 2.0')

        const authrDataStruct = parseAuthData(attestationStruct.authData);
        console.log('===================================================')
        console.log("pubArea", parsePubArea(attestationStruct.attStmt.pubArea))
        console.log('===================================================')
        console.log("certInfo", parseCertInfo(attestationStruct.attStmt.certInfo));
        console.log('===================================================')
        let x5c = [];
        for(let cert of attestationStruct.attStmt.x5c) {
            cert = base64ToPem(cert.toString('base64'))
            x5c.push(cert)
        }
        console.log("attcert", x5c)
        console.log('===================================================')
        const pubAreaStruct = parsePubArea(attestationStruct.attStmt.pubArea);
        const pubKeyCose = cbor.decodeAllSync(authrDataStruct.COSEPublicKey)[0];
        const certInfoStruct = parseCertInfo(attestationStruct.attStmt.certInfo);
        if(Buffer.compare(pubAreaStruct.unique, pubKeyCose.get(COSEKEYS.crv)))
            throw new Error("pubArea.unique is not set to newly generated public key")

        if(parseCertInfo(attestationStruct.attStmt.certInfo).magic.toString(16) !== "ff544347")
            throw new Error('magic is not TPM_GENERATED')

        if (certInfoStruct.type !== 'TPM_ST_ATTEST_CERTIFY')
            throw new Error('type is not TPM_ST_ATTEST_CERTIFY')
        
        const clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        const attToBeSigned = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
        const attToBeSignedSHA256Hashed = hash('sha256', attToBeSigned)
        const attToBeSignedSHA1Hashed = hash('sha1', attToBeSigned)

        if (Buffer.compare(certInfoStruct.extraData, attToBeSignedSHA256Hashed) && Buffer.compare(certInfoStruct.extraData, attToBeSignedSHA1Hashed))
            throw new Error('certInfo.extraData is not equals to attToBeSignedHash .')

        response.verified = true;

    } else if (attestationStruct.fmt === 'android-safetynet') {
        const jwsString = attestationStruct.attStmt.response.toString('utf8');
        const jwsParts = jwsString.split('.');
        const HEADER = JSON.parse(base64url.decode(jwsParts[0]));
        const PAYLOAD = JSON.parse(base64url.decode(jwsParts[1]));
        const SIGNATURE = jwsParts[2];
        const clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        const nonceBase = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
        const nonceBuffer = hash('sha256', nonceBase);
        const expectedNonce = nonceBuffer.toString('base64');

        if (!attestationStruct.attStmt.ver)
            throw new Error('ver field is empty.')

        if (PAYLOAD.nonce !== expectedNonce)
            throw new Error(`PAYLOAD.nonce does not contains expected nonce! Expected ${PAYLOAD.nonce} to equal ${expectedNonce}!`)

        if (PAYLOAD.ctsProfileMatch === false)
            throw new Error('PAYLOAD.ctsProfileMatch is false!')

        const date = new Date().getTime();
        if (date <= PAYLOAD.timestampMs)
            throw new Error('PAYLOAD.timestampMs is future!')

        if (PAYLOAD.timestampMs <= date - (60 * 1000))
            throw new Error('PAYLOAD.timestampMs is older than 1 minute!')

        const certPath = HEADER.x5c.concat([gsr2]).map((cert) => {
            let pemcert = '';
            for (let i = 0; i < cert.length; i += 64) { pemcert += cert.slice(i, i + 64) + '\n' }

            return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----'
        })

        if (getCertificateInfo(certPath[0]).subject.CN !== 'attest.android.com')
            throw new Error('The common name is not set to "attest.android.com"!')

        //validateCertificatePath(certPath)
        const signatureBaseBuffer = Buffer.from(jwsParts[0] + '.' + jwsParts[1]);
        const certificate = certPath[0];
        const signatureBuffer = base64url.toBuffer(SIGNATURE);

        const signatureIsValid = crypto.createVerify('sha256')
            .update(signatureBaseBuffer)
            .verify(certificate, signatureBuffer)

        if (!signatureIsValid)
            throw new Error('Failed to verify the signature!')

        response.verified = true;

    }

    return response
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

    if (!verifyBase64Url(webAuthnResponse.body.response.authenticatorData))
        throw new Error('AuthenticatorData is not base64url encoded');

    if (webAuthnResponse.body.response.userHandle && typeof webAuthnResponse.body.response.userHandle !== 'string')
        throw new Error('userHandle is not of type DOMString');

    if (!verifyBase64Url(webAuthnResponse.body.response.signature))
        throw new Error('Signature is not base64url encoded');

    const authenticatorData = base64url.toBuffer(webAuthnResponse.body.response.authenticatorData);

    let response = { 'verified': false }
    const authrDataStruct = parseAuthData(authenticatorData);

    if (Buffer.compare(authrDataStruct.rpIdHash, hash('sha256', Buffer.from(webAuthnResponse.hostname))) !== 0)
        throw new Error('rpIdHash don\'t match!')

    verifyUserVerification(authrDataStruct.flags, userVerification);

    const clientDataHash = hash('sha256', base64url.toBuffer(webAuthnResponse.body.response.clientDataJSON));
    const signatureBase = Buffer.concat([authenticatorData, clientDataHash]);
    const publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
    const signature = base64url.toBuffer(webAuthnResponse.body.response.signature);
    response.verified = verifySignature(signature, signatureBase, publicKey);

    if (response.verified) {
        if (authrDataStruct.counter !== 0 && authr.counter !== 0 && authrDataStruct.counter <= authr.counter) { throw new Error('Authr counter did not increase!') }

        authr.counter = authrDataStruct.counter;
    }

    return response

}

const verifyPackedAttestation = (webAuthnResponse) => {
    let response = { 'verified': false };
    const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
    const authDataStruct = parseAuthData(attestationStruct.authData);

    if (!authDataStruct.flags.up)
        throw new Error('User was NOT presented durring authentication!');
    verifyUserVerification(authDataStruct.flags);

    if (!attestationStruct.attStmt.alg)
        throw new Error('attStmt.alg is missing');

    if (!COSEALGHASH.hasOwnProperty(attestationStruct.attStmt.alg))
        throw new Error('attStmt.alg is not support.')

    if (typeof attestationStruct.attStmt.alg !== 'number')
        throw new Error('attStmt.alg is Not a Number');

    const clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    const signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);

    const signatureBuffer = attestationStruct.attStmt.sig;
    let publicKey = undefined;

    if (attestationStruct.attStmt.x5c) {
        /* ----- Verify FULL attestation ----- */
        publicKey = base64url.encode(COSEECDHAtoPKCS(authDataStruct.COSEPublicKey));
        const leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
        if (attestationStruct.attStmt.x5c.length > 1) {
            let certPath = attestationStruct.attStmt.x5c.map((cert) => {
                cert = cert.toString('base64');

                let pemcert = '';
                for (let i = 0; i < cert.length; i += 64)
                    pemcert += cert.slice(i, i + 64) + '\n';

                return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
            })
            validateCertificatePath(certPath);
        }
        const certInfo = getCertificateInfo(leafCert);

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
        const pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
        const hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
        if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
            const x = pubKeyCose.get(COSEKEYS.x);
            const y = pubKeyCose.get(COSEKEYS.y);
            const ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);
            const signatureBaseHash = hash(hashAlg, signatureBaseBuffer);
            const ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
            const key = ec.keyFromPublic(ansiKey);
            publicKey = base64url.encode(ansiKey);
            response.verified = key.verify(signatureBaseHash, signatureBuffer);
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
            const signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];
            const key = new NodeRSA(undefined, { signingScheme });
            key.importKey({
                n: pubKeyCose.get(COSEKEYS.n),
                e: 65537,
            }, 'components-public');
            response.verified = key.verify(signatureBaseBuffer, signatureBuffer)
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
            const x = pubKeyCose.get(COSEKEYS.x);
            const signatureBaseHash = hash(hashAlg, signatureBaseBuffer);
            const key = new elliptic.eddsa('ed25519');
            key.keyFromPublic(x);
            publicKey = key;
            response.verified = key.verify(signatureBaseHash, signatureBuffer);
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
    verifyBase64Url,
    randomBase64URLBuffer,
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse
}
