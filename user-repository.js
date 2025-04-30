import DBLocal from 'db-local';
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';

import { SALT_ROUNDS } from './config.js';
import { Validation } from './validation.js';

const { Schema } = new DBLocal({ path: './db' });

const User = Schema('User', {
  _id: { type: 'string', required: true },
  username: { type: 'string', required: true, unique: true },
  password: { type: 'string', required: true }
})

export class UserRepository {
  static async create({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    const user = User.findOne({ username });
    if (user) {
      throw new Error('User already exists.');
    }

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save();

    return id;
  };
  static async login({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    const user = User.findOne({ username });
    if (!user) {
      throw new Error('User does not exist.');
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new Error('Invalid password.');
    }
    const { password: _, ...publicUser } = user;
    return publicUser;
  }

}