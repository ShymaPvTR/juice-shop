/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt as jwt } from 'express-jwt'
import jsonwebtoken from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import bcrypt from 'bcrypt'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

// Generate secure random keys instead of hardcoded ones
const generateSecureKey = () => crypto.randomBytes(256).toString('base64')

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : generateSecureKey()
const privateKey = process.env.JWT_PRIVATE_KEY || generateSecureKey()

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

// Replace MD5 with SHA-256 for better security
export const hash = (data: string) => crypto.createHash('sha256').update(data).digest('hex')

// Use bcrypt for password hashing
export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12
  return await bcrypt.hash(password, saltRounds)
}

export const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash)
}

// Use a secure secret for HMAC
const hmacSecret = process.env.HMAC_SECRET || crypto.randomBytes(64).toString('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacSecret).update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// Updated JWT middleware with proper configuration
export const isAuthorized = () => jwt({
  secret: publicKey,
  algorithms: ['RS256'],
  credentialsRequired: true,
  getToken: (req: Request) => {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1]
    } else if (req.query && req.query.token) {
      return req.query.token as string
    } else if (req.cookies && req.cookies.token) {
      return req.cookies.token
    }
    return null
  }
})

export const denyAll = () => jwt({ 
  secret: crypto.randomBytes(32).toString('hex'),
  algorithms: ['HS256']
})

export const authorize = (user = {}) => jsonwebtoken.sign(user, privateKey, { 
  expiresIn: '6h', 
  algorithm: 'RS256',
  issuer: 'juice-shop',
  audience: 'juice-shop-users'
})

export const verify = (token: string) => {
  try {
    return token ? jsonwebtoken.verify(token, publicKey, { algorithms: ['RS256'] }) : false
  } catch (error) {
    return false
  }
}

export const decode = (token: string) => {
  try {
    return jsonwebtoken.decode(token)
  } catch (error) {
    return null
  }
}

// Enhanced HTML sanitization
export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html, {
  allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
  allowedAttributes: {
    'a': ['href']
  },
  allowedSchemes: ['http', 'https', 'mailto']
})

export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)

export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// Fixed redirect allowlist with exact URL matching
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

// Secure redirect validation - exact URL match only
export const isRedirectAllowed = (url: string) => {
  try {
    const parsedUrl = new URL(url)
    // Only allow HTTPS and HTTP protocols
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return false
    }
    // Exact match against allowlist
    return redirectAllowlist.has(url)
  } catch (error) {
    // Invalid URL
    return false
  }
}

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmacInstance = crypto.createHmac('sha256', privateKey)
  return hmacInstance.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = utils.jwtFrom(req)
      const decodedToken = verify(token)
      if (decodedToken && typeof decodedToken === 'object' && 'data' in decodedToken) {
        const userData = decodedToken.data as any
        if (userData?.role === roles.accounting) {
          next()
        } else {
          res.status(403).json({ error: 'Malicious activity detected' })
        }
      } else {
        res.status(401).json({ error: 'Invalid token' })
      }
    } catch (error) {
      res.status(401).json({ error: 'Authentication failed' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  try {
    const token = utils.jwtFrom(req)
    const decodedToken = verify(token)
    if (decodedToken && typeof decodedToken === 'object' && 'data' in decodedToken) {
      const userData = decodedToken.data as any
      return userData?.role === roles.deluxe && 
             userData?.deluxeToken && 
             userData?.deluxeToken === deluxeToken(userData?.email)
    }
    return false
  } catch (error) {
    return false
  }
}

export const isCustomer = (req: Request) => {
  try {
    const token = utils.jwtFrom(req)
    const decodedToken = verify(token)
    if (decodedToken && typeof decodedToken === 'object' && 'data' in decodedToken) {
      const userData = decodedToken.data as any
      return userData?.role === roles.customer
    }
    return false
  } catch (error) {
    return false
  }
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = utils.jwtFrom(req)
      const user = authenticatedUsers.tokenMap[token]
      if (user && user.data && user.data.id) {
        req.body.UserId = user.data.id
        next()
      } else {
        res.status(401).json({ status: 'error', message: 'User not authenticated' })
      }
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: 'Authentication failed' })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    try {
      const decoded = jsonwebtoken.verify(token, publicKey, { algorithms: ['RS256'] })
      if (decoded && authenticatedUsers.get(token) === undefined) {
        authenticatedUsers.put(token, decoded as ResponseWithUser)
        res.cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict'
        })
      }
    } catch (error) {
      // Invalid token, clear cookie
      res.clearCookie('token')
    }
  }
  next()
}