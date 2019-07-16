const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const elliptic = require('elliptic');
const NodeRSA = require('node-rsa');
const utils = require('./utils');

const gsr2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==';
const androidkeystoreroot = 'MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw=='

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
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @param  {String} attestation    - attestation
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
const generateServerMakeCredRequest = (username, displayName, id, attestation) => {
    return {
        challenge: utils.randomBase64URLBuffer(32),

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
 * Tries to verify AuthenticatorAttestationResponse
 * @param  {Object} webAuthnResponse 
 * @return {Object}                   - verification result  
 */
const verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

    let response = { 'verified': false };
    if (attestationStruct.fmt === 'none') {
        const authrDataStruct = utils.parseAuthData(attestationStruct.authData);
        if (attestationStruct.attStmt.x5c)
            throw new Error('Send attestation FULL packed with fmt set none.');

        if (!authrDataStruct.flags.up)
            throw new Error('User was NOT presented durring authentication!');

        const publicKey = utils.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
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
        const authrDataStruct = utils.parseAuthData(attestationStruct.authData);

        if (!(authrDataStruct.flags.up))
            throw new Error('User was NOT presented durring authentication!');

        if (Number(authrDataStruct.aaguid.toString('hex')) !== 0)
            throw new Error('authData.AAGUID is not 0x00');

        const clientDataHash = utils.hash('SHA256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        const reservedByte = Buffer.from([0x00]);
        const publicKey = utils.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
        const signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        const PEMCertificate = utils.ASN1toPEM(attestationStruct.attStmt.x5c[0]);
        const signature = attestationStruct.attStmt.sig;

        response.verified = utils.verifySignature(signature, signatureBase, PEMCertificate);

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
    } else if (attestationStruct.fmt === 'android-key') {
        const authrDataStruct = utils.parseAuthData(attestationStruct.authData);
        const clientDataHash = utils.hash('SHA256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        const signatureBase = Buffer.concat([attestationStruct.authData, clientDataHash])
        const leafCert = utils.base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'))
        const signature = attestationStruct.attStmt.sig
        response.verified = utils.verifySignature(signature, signatureBase, leafCert)
        if (!response.verified)
            throw new Error('Failed to verify the signature!')

        const attestationRootCertificateBuffer = attestationStruct.attStmt.x5c[attestationStruct.attStmt.x5c.length - 1]
        if (attestationRootCertificateBuffer.toString('base64') !== androidkeystoreroot)
            throw new Error('Attestation root is not invalid!')

        const certPath = attestationStruct.attStmt.x5c.map((cert) => {
            cert = cert.toString('base64')

            let pemcert = ''
            for (let i = 0; i < cert.length; i += 64) { pemcert += cert.slice(i, i + 64) + '\n' }

            return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----'
        })

        utils.validateCertificatePath(certPath)
        const certASN1 = asn1.decode(attestationStruct.attStmt.x5c[0])
        /* ----- VERIFY PUBLIC KEY MATCHING ----- */
        const certJSON = asn1ObjectToJSON(certASN1)
        const certTBS = certJSON.data[0]
        const certPubKey = certTBS.data[6]
        const certPubKeyBuff = certPubKey.data[1].data

        /* CHECK PUBKEY */
        const coseKey = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0]

        /* ANSI ECC KEY is 0x04 with X and Y coefficients. But certs have it padded with 0x00 so for simplicity it easier to do it that way */
        const ansiKey = Buffer.concat([Buffer([0x00, 0x04]), coseKey.get(COSEKEYS.x), coseKey.get(COSEKEYS.y)])

        if (ansiKey.toString('hex') !== certPubKeyBuff.toString('hex')) { throw new Error('Certificate public key does not match public key in authData') }
        /* ----- VERIFY PUBLIC KEY MATCHING ENDS ----- */

        /* ----- VERIFY CERTIFICATE REQUIREMENTS ----- */
        const AttestationExtension = findOID(certASN1, '1.3.6.1.4.1.11129.2.1.17')
        const AttestationExtensionJSON = asn1ObjectToJSON(AttestationExtension)

        const attestationChallenge = AttestationExtensionJSON.data[1].data[0].data[4].data

        if (attestationChallenge.toString('hex') !== clientDataHashBuf.toString('hex')) { throw new Error('Certificate attestation challenge is not set to the clientData hash!') }

        const softwareEnforcedAuthz = AttestationExtensionJSON.data[1].data[0].data[6].data
        const teeEnforcedAuthz = AttestationExtensionJSON.data[1].data[0].data[7].data

        if (containsASN1Tag(softwareEnforcedAuthz, 600) || containsASN1Tag(teeEnforcedAuthz, 600)) { throw new Error('TEE or Software autherisation list contains "allApplication" flag, which means that credential is not bound to the RP!') }
        /* ----- VERIFY CERTIFICATE REQUIREMENTS ENDS ----- */

        if (response.verified) {
            response.authrInfo = {
                fmt: 'android-key',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: authrDataStruct.credID
            }
        }


    } else if (attestationStruct.fmt === 'android-safetynet') {
        const jwsString = attestationStruct.attStmt.response.toString('utf8');
        const jwsParts = jwsString.split('.');
        const HEADER = JSON.parse(base64url.decode(jwsParts[0]));
        const PAYLOAD = JSON.parse(base64url.decode(jwsParts[1]));
        const SIGNATURE = jwsParts[2];
        const clientDataHashBuf = utils.hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
        const nonceBase = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
        const nonceBuffer = utils.hash('sha256', nonceBase);
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

        if (utils.getCertificateInfo(certPath[0]).subject.CN !== 'attest.android.com')
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

const verifyPackedAttestation = (webAuthnResponse) => {
    let response = { 'verified': false };
    const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    const attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];
    const authDataStruct = utils.parseAuthData(attestationStruct.authData);

    if (!authDataStruct.flags.up)
        throw new Error('User was NOT presented durring authentication!');
    utils.verifyUserVerification(authDataStruct.flags);

    if (!attestationStruct.attStmt.alg)
        throw new Error('attStmt.alg is missing');

    if (!COSEALGHASH.hasOwnProperty(attestationStruct.attStmt.alg))
        throw new Error('attStmt.alg is not support.')

    if (typeof attestationStruct.attStmt.alg !== 'number')
        throw new Error('attStmt.alg is Not a Number');

    const clientDataHashBuf = utils.hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    const signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);

    const signatureBuffer = attestationStruct.attStmt.sig;
    let publicKey = undefined;

    if (attestationStruct.attStmt.x5c) {
        /* ----- Verify FULL attestation ----- */
        publicKey = base64url.encode(utils.COSEECDHAtoPKCS(authDataStruct.COSEPublicKey));
        const leafCert = utils.base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
        if (attestationStruct.attStmt.x5c.length > 1) {
            let certPath = attestationStruct.attStmt.x5c.map((cert) => {
                cert = cert.toString('base64');

                let pemcert = '';
                for (let i = 0; i < cert.length; i += 64)
                    pemcert += cert.slice(i, i + 64) + '\n';

                return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
            })
            utils.validateCertificatePath(certPath);
        }
        const certInfo = utils.getCertificateInfo(leafCert);

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
            const signatureBaseHash = utils.hash(hashAlg, signatureBaseBuffer);
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
            const signatureBaseHash = utils.hash(hashAlg, signatureBaseBuffer);
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
    generateServerMakeCredRequest,
    verifyAuthenticatorAttestationResponse,
}
