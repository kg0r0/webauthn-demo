const express  = require('express');
const router   = express.Router();
const database = require('./db');

/* Returns if user is logged in */
router.get('/isLoggedIn', (request, response) => {
    if(!request.session.loggedIn) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Not Logged in.'
        })
    } else {
        response.json({
            'status': 'ok'
        })
    }
})

/* Logs user out */
router.get('/logout', (request, response) => {
    request.session.loggedIn = false;
    request.session.username = undefined;
    response.json({
        'status': 'ok'
    })
})

/* Returns personal info and THE SECRET INFORMATION */
router.get('/personalInfo', (request, response) => {
    if(!request.session.loggedIn) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Access denied'
        })
    } else {
        response.json({
            'status': 'ok',
            'name': database[request.session.username].name,
        })
    }
})

module.exports = router;
