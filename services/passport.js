const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('../models/user');
const config = require('../config');

// Setup options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // See if the user ID ine the payload exist in our database
    // If it does, call 'done with that user
    // Otherwise, call done without a user object
    User.findById(payload.sub, function(err, user) {
        if (err) { return done(err, false); }

        if( user) {
            done(null, user);
        } else {
            done(null, false);
        }
    });
});

// Setup options for Local Strategy
const localOptions = {
    usernameField: 'email'
};

// Create Local Strategy
const localLogin = new LocalStrategy( localOptions, function(email, password, done) {
    // verify this username and password, call done with the user
    // otherwise, call done with false
    User.findOne({ email: email }, function (err, user) {
        if(err) { done(err) }

        if(!user) { return done(null, false )}

        // Compare passwords
        user.comparePassword(password, function(err, isMatch) {
            if (err) { return done(err); }
            if (!isMatch) { return done(null, false); }

            return done(null, user);
        })
    })
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);