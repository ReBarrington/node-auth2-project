const jwt = require('jsonwebtoken');
const secrets = require('../api/secrets.js');

module.exports = (req, res, next) => {
    // tokens are usually sent as the Authorization header
    const token = req.headers.authorization;
    const secret = secrets.jwtSecret;

    if (token) {
        // verify for validity:
        jwt.verify(token, secret, (error, decodedToken) => {
            // if good, error will be undefined
            if (error) {
                res.status(401).json({ message: "You shall not pass!"})
            } else {
                req.decodedToken = decodedToken;
                next();
            }
        });
    } else {
        // no token:
        res.status(400).json({ message: "Please provide credentials."})
    }
};
