const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');
const ldap2date = require('ldap2date');

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
const isBase64UrlEncoded = (str) => {
    return !!str.match(/^[A-Za-z0-9\-_]+={0,2}$/);
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


module.exports = {
    isBase64UrlEncoded,
    randomBase64URLBuffer,
    parseAuthData,
    ASN1toPEM,
    COSEECDHAtoPKCS,
    hash,
    getCertificateInfo,
    validateCertificatePath,
    verifySignature,
    base64ToPem,
    verifyUserVerification
}
