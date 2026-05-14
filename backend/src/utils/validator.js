const validator = require("validator");

const validate = (data) => {
    const mandatoryField = ['firstName', "emailId", 'password'];
    const IsAllowed = mandatoryField.every((k) => Object.keys(data).includes(k));

    if (!IsAllowed)
        throw new Error("Some Field Missing");

    if (!validator.isEmail(data.emailId))
        throw new Error("Invalid Email");

    if (!validator.isStrongPassword(data.password, {
        minLength: 8,
        minLowercase: 0,  // ✅ relaxed
        minUppercase: 0,  // ✅ relaxed
        minNumbers: 0,    // ✅ relaxed
        minSymbols: 0,    // ✅ relaxed
    }))
        throw new Error("Password must be at least 8 characters");
}

module.exports = validate;