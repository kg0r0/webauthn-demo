const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');
const ldap2date = require('ldap2date');
const request = require('request');
const jose = require("node-jose");
const config = require('../config.json');
const database = require('../routes/db');

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

const fidoMdsRootCert =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG\n" +
    "A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk\n" +
    "YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX\n" +
    "DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs\n" +
    "aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS\n" +
    "b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+\n" +
    "AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims\n" +
    "rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw\n" +
    "DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw\n" +
    "HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw\n" +
    "ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW\n" +
    "DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU\n" +
    "YjdBz56jSA==\n" +
    "-----END CERTIFICATE-----\n";

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

const mdsClient = () => {
    database.toc = {}
    database.metadataStatement = {}
    const endpoints = config["mds-endpoints"]
    for(let endpoint of endpoints) {
        const url = config.token ? endpoint+"?token="+config.token : endpoint
        const options = {
            url,
            method: 'GET'
        }
        request(options, (err, response, body) => {
            if (err) {
                throw new Error(err.message);
            }
            jose.JWS.createVerify().verify(body, { allowEmbeddedKey: true }).then((parsedJws) => {
                database["tocStruct"] = parsedJws;
                for(let entry of JSON.parse(parsedJws.payload.toString()).entries) {
                    database.toc[entry.aaguid] = entry
                    request(entry.url, (err, response, body) => {
                        if (err) {
                            throw new Error(err.message);
                        }
                        database.metadataStatement[entry.aaguid] = JSON.parse(base64url.decode(body));
                    })
                }
            }, (err) => {
                console.log(`${err.message} : ${url}`)
            })
        })
    }
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
    verifyUserVerification,
    parsePubArea,
    parseCertInfo,
    mdsClient,
}
