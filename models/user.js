const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define the user model
const userSchema = new Schema({
    email: { type: String, unique: true, lowercase: true},
    password: String
});

// onSave hook
userSchema.pre('save', function(next) {
    const user = this;

    bcrypt.genSalt(10, function(err, salt) {
        if(err) { return next(err)}

        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if(err) { return next(err)}

            user.password = hash;
            next();
        });
    });
});

// Verify the password
userSchema.methods.comparePassword = function (candidatePassword, callback){
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if(err) { return callback(err); }

        callback(null, isMatch);
    });
};

// Create the model Class
const ModelClass = mongoose.model('User', userSchema);

// Export the model
module.exports = ModelClass;