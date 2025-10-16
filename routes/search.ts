/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import * as utils from '../lib/utils'
import * as models from '../models/index'
import { UserModel } from '../models/user'
import { ProductModel } from '../models/product'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// Input validation and sanitization
function sanitizeSearchCriteria(criteria: string): string {
  if (!criteria || typeof criteria !== 'string') {
    return ''
  }
  
  // Limit length
  criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200)
  
  // Remove potentially dangerous characters for SQL injection
  criteria = criteria.replace(/['"\\;]/g, '')
  
  // Trim whitespace
  criteria = criteria.trim()
  
  return criteria
}

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    
    // Sanitize input
    criteria = sanitizeSearchCriteria(criteria)
    
    // Use Sequelize ORM with parameterized queries to prevent SQL injection
    ProductModel.findAll({
      where: {
        [Op.and]: [
          {
            [Op.or]: [
              {
                name: {
                  [Op.like]: `%${criteria}%`
                }
              },
              {
                description: {
                  [Op.like]: `%${criteria}%`
                }
              }
            ]
          },
          {
            deletedAt: {
              [Op.is]: null
            }
          }
        ]
      },
      order: [['name', 'ASC']],
      raw: true
    })
    .then((products: any[]) => {
      const dataString = JSON.stringify(products)
      
      // Challenge logic (maintained for compatibility but secured)
      if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) {
        let solved = true
        UserModel.findAll({ raw: true }).then(users => {
          const userData = utils.queryResultToJson(users)
          if (userData.data?.length) {
            for (let i = 0; i < userData.data.length; i++) {
              solved = solved && utils.containsOrEscaped(dataString, userData.data[i].email) && utils.contains(dataString, userData.data[i].password)
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
        // Use parameterized query for schema information
        models.sequelize.query(
          'SELECT sql FROM sqlite_master WHERE type = :type',
          {
            replacements: { type: 'table' },
            type: models.sequelize.QueryTypes.SELECT
          }
        ).then((data: any) => {
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
        }).catch((error: Error) => {
          next(error)
        })
      }
      
      // Translate product names and descriptions
      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name)
        products[i].description = req.__(products[i].description)
      }
      
      res.json(utils.queryResultToJson(products))
    })
    .catch((error: ErrorWithParent) => {
      next(error.parent || error)
    })
  }
}