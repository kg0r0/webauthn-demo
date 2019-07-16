const express   = require('express');
const utils     = require('../libs/utils');
const attestation     = require('../libs/attestation');
const assertion     = require('../libs/assertion');
const config    = require('../config.json');
const base64url = require('base64url');
const router    = express.Router();
const database  = require('./db');


router.post('/options', (request, response) => {
    if(!request.body || !request.body.username) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Request missing username field!'
        })
        return
    }

    let username = request.body.username;

    if(!database[username] || !database[username].registered) {
        response.json({
            'status': 'failed',
            'errorMessage': `User ${username} does not exist!`
        })

        return
    }

    let getAssertion    = assertion.generateServerGetAssertion(database[username].authenticators)
    getAssertion.status = 'ok';
    getAssertion.errorMessage = '';
    getAssertion.extensions = request.body.extensions;
    getAssertion.userVerification = request.body.userVerification || 'preferred';
    request.session.challenge = getAssertion.challenge;
    request.session.username  = username;
    request.session.userVerification = getAssertion.userVerification;

    response.json(getAssertion)
})

router.post('/result', (request, response) => {
    if(!request.body       || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' ) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })
        return
    }
    
    if (!utils.isBase64UrlEncoded(request.body.id)) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Invalid id!'
        })
        return
    }

    const clientData   = JSON.parse(base64url.decode(request.body.response.clientDataJSON));

    /* Check challenge... */
    if(clientData.challenge !== request.session.challenge) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Challenges don\'t match!'
        })
    }

    /* ...and origin */
    if(clientData.origin !== config.origin) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Origins don\'t match!'
        })
    }

    /* ...and type */
    if(clientData.type !== 'webauthn.get') {
        response.json({
            'status': 'failed',
            'errorMessage': 'Type don\'t match!'
        }) 
    }

    /* ...and tokenBinding */
    if(clientData.tokenBinding) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Token Binding don\`t support!'
        }) 
    }

    let result;
    if(request.body.response.authenticatorData) {
        /* This is get assertion */
        result = assertion.verifyAuthenticatorAssertionResponse(request, database[request.session.username].authenticators, request.session.userVerification);
    } else {
        response.json({
            'status': 'failed',
            'errorMessage': 'Can not determine type of response!'
        })
    }

    if(result.verified) {
        request.session.loggedIn = true;
        response.json({
            'status': 'ok',
            'errorMessage': ''
        })
    } else {
        response.json({
            'status': 'failed',
            'errorMessage': 'Can not authenticate signature!'
        })
    }
})

module.exports = router;
