const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator/check');

// @route GET api/auth
// @desc Test route
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        console.log(error.message),
            res.status(500).json({
                msg: 'User do not have in the server'
            });
    }
});

// @route POST api/users
// @desc Authenticate user and get token
// @access Public
router.post('/', [
    check('password', 'Passowrd is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
], (req, res) => { login(req, res) });

login = async (req, res) => {
    const errors = validationResult(req);
    const { password, email } = req.body;
    if (!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        });
    }
    
    try {
        let user = await User.findOne({ email });
        if (!user) {
            res.status(400).json({
                errors: [{
                    msg: 'Invalid Crendtials'
                }]
            })
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(400).json({
                errors: [{
                    msg: 'Invalid Crendtials'
                }]
            })
        }

        // Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), { expiresIn: 360000 },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            });

    } catch (error) {
        console.error(err.message);
        res.status(500).send('Server error');

    }
};

module.exports = router;