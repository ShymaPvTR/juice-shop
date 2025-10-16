/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'
import validator from 'validator'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as models from '../models/index'
import { type User } from '../data/types'
import * as utils from '../lib/utils'

// Input validation and sanitization
function validateLoginInput(email: string, password: string): { isValid: boolean, errors: string[] } {
  const errors: string[] = []
  
  // Validate email
  if (!email || typeof email !== 'string') {
    errors.push('Email is required')
  } else if (!validator.isEmail(email)) {
    errors.push('Invalid email format')
  } else if (email.length > 254) {
    errors.push('Email too long')
  }
  
  // Validate password
  if (!password || typeof password !== 'string') {
    errors.push('Password is required')
  } else if (password.length > 1000) {
    errors.push('Password too long')
  }
  
  return {
    isValid: errors.length === 0,
    errors
  }
}

export function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user)
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id // keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      verifyPreLoginChallenges(req)
      
      const email = req.body.email || ''
      const password = req.body.password || ''
      
      // Validate input
      const validation = validateLoginInput(email, password)
      if (!validation.isValid) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid input',
          errors: validation.errors
        })
      }
      
      // Use Sequelize ORM with parameterized queries to prevent SQL injection
      const authenticatedUser = await UserModel.findOne({
        where: {
          email: email,
          deletedAt: null
        },
        raw: true
      })
      
      if (!authenticatedUser) {
        return res.status(401).send(res.__('Invalid email or password.'))
      }
      
      // Verify password using secure comparison
      let passwordValid = false
      
      // Check if password is hashed with bcrypt (new secure method)
      if (authenticatedUser.password.startsWith('$2b$')) {
        passwordValid = await security.verifyPassword(password, authenticatedUser.password)
      } else {
        // Fallback for existing MD5 hashes (should be migrated)
        passwordValid = authenticatedUser.password === security.hash(password)
        
        // If login successful with old hash, update to bcrypt
        if (passwordValid) {
          const newHashedPassword = await security.hashPassword(password)
          await UserModel.update(
            { password: newHashedPassword },
            { where: { id: authenticatedUser.id } }
          )
        }
      }
      
      if (!passwordValid) {
        return res.status(401).send(res.__('Invalid email or password.'))
      }
      
      const user = utils.queryResultToJson(authenticatedUser)
      
      if (user.data?.id && user.data.totpSecret !== '') {
        res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.data.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
      } else if (user.data?.id) {
        // @ts-expect-error FIXME some properties missing in user
        afterLogin(user, res, next)
      } else {
        res.status(401).send(res.__('Invalid email or password.'))
      }
    } catch (error: Error) {
      next(error)
    }
  }

  function verifyPreLoginChallenges (req: Request) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => { return req.body.email === 'admin@' + config.get<string>('application.domain') && req.body.password === 'admin123' })
    challengeUtils.solveIf(challenges.loginSupportChallenge, () => { return req.body.email === 'support@' + config.get<string>('application.domain') && req.body.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P' })
    challengeUtils.solveIf(challenges.loginRapperChallenge, () => { return req.body.email === 'mc.safesearch@' + config.get<string>('application.domain') && req.body.password === 'Mr. N00dles' })
    challengeUtils.solveIf(challenges.loginAmyChallenge, () => { return req.body.email === 'amy@' + config.get<string>('application.domain') && req.body.password === 'K1f.....................' })
    challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => { return req.body.email === 'J12934@' + config.get<string>('application.domain') && req.body.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB' })
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return req.body.email === 'bjoern.kimminich@gmail.com' && req.body.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    challengeUtils.solveIf(challenges.exposedCredentialsChallenge, () => { return req.body.email === 'testing@' + config.get<string>('application.domain') && req.body.password === 'IamUsedForTesting' })
  }

  function verifyPostLoginChallenges (user: { data: User }) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => { return user.data.id === users.admin.id })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => { return user.data.id === users.jim.id })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => { return user.data.id === users.bender.id })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => { return user.data.id === users.chris.id })
    if (challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) && user.data.email === 'acc0unt4nt@' + config.get<string>('application.domain') && user.data.role === 'accounting') {
      UserModel.count({ where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') } }).then((count: number) => {
        if (count === 0) {
          challengeUtils.solve(challenges.ephemeralAccountantChallenge)
        }
      }).catch(() => {
        throw new Error('Unable to verify challenges! Try again')
      })
    }
  }
}