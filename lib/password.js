// var passwordHash = require('password-hash');
var bcrypt = require('bcrypt');

var SALT_WORK_FACTOR = 10;

module.exports = function(self) {
  self.hashPassword = function(password) {
    // return passwordHash.generate(password);
    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
    	if(!err) bcrypt.hash(password, salt, function(err, hash) {
    		cback(hash);
    	});
    	else console.log("hashPassword ERROR: " + err);
    });
  };
};

