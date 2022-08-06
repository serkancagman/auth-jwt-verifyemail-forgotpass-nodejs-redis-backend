import Joi from "joi";

const schema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required().min(6),
  name: Joi.string().min(2).max(50),
  surname:Joi.string().min(2).max(50),
  phone: Joi.string().min(7).max(15),
  country:Joi.string(),
  email_verified:Joi.boolean()
});

export default schema;
