/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import * as utils from '../lib/utils'
import * as models from '../models/index'
import { ProductModel } from '../models/product'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    
    // Input validation and sanitization
    if (typeof criteria !== 'string') {
      return res.status(400).json({ error: 'Invalid search criteria' })
    }
    
    criteria = criteria.trim()
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    
    // Sanitize input to prevent malicious characters
    criteria = criteria.replace(/[<>'"]/g, '')
    
    // Use parameterized query with Sequelize ORM to prevent SQL injection
    ProductModel.findAll({
      where: {
        [Op.and]: [
          {
            [Op.or]: [
              { name: { [Op.like]: `%${criteria}%` } },
              { description: { [Op.like]: `%${criteria}%` } }
            ]
          },
          { deletedAt: null }
        ]
      },
      order: [['name', 'ASC']],
      attributes: { exclude: ['createdAt', 'updatedAt'] } // Limit exposed data
    })
      .then((products: any) => {
        const dataString = JSON.stringify(products)
        
        // Challenge verification logic (preserved for educational purposes)
        if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
          let solved = true
          UserModel.findAll().then(data => {
            const users = utils.queryResultToJson(data)
            if (users.data?.length) {
              for (let i = 0; i < users.data.length; i++) {
                solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
                if (!solved) {
                  break
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.unionSqlInjectionChallenge)
              }
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
        if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
          let solved = true
          void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
            const tableDefinitions = utils.queryResultToJson(data)
            if (tableDefinitions.data?.length) {
              for (let i = 0; i < tableDefinitions.data.length; i++) {
                if (tableDefinitions.data[i].sql) {
                  solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                  if (!solved) {
                    break
                  }
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.dbSchemaChallenge)
              }
            }
          })
        } // vuln-code-snippet hide-end
        
        // Translate product names and descriptions
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        // Generic error message to prevent information disclosure
        res.status(500).json({ error: 'Search operation failed' })
      })
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge