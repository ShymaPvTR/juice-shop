/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import crypto from 'node:crypto'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

// File type validation using magic numbers
const ALLOWED_FILE_SIGNATURES = {
  pdf: ['25504446'], // %PDF
  xml: ['3c3f786d6c', '3c21444f43545950452068746d6c'], // <?xml, <!DOCTYPE html
  zip: ['504b0304', '504b0506', '504b0708'], // ZIP signatures
  yml: [], // Text files don't have reliable magic numbers
  yaml: []
}

// Maximum file sizes (in bytes)
const MAX_FILE_SIZES = {
  pdf: 10 * 1024 * 1024, // 10MB
  xml: 1 * 1024 * 1024,  // 1MB
  zip: 50 * 1024 * 1024, // 50MB
  yml: 1 * 1024 * 1024,  // 1MB
  yaml: 1 * 1024 * 1024  // 1MB
}

// Sanitize file names to prevent path traversal
function sanitizeFileName(fileName: string): string {
  if (!fileName || typeof fileName !== 'string') {
    return 'unknown'
  }
  
  // Remove path separators and dangerous characters
  const sanitized = fileName
    .replace(/[/\\]/g, '') // Remove path separators
    .replace(/\.\./g, '')  // Remove parent directory references
    .replace(/[<>:"|?*]/g, '') // Remove dangerous characters
    .replace(/^\.+/, '')   // Remove leading dots
    .trim()
  
  // Ensure filename is not empty and has reasonable length
  if (sanitized.length === 0) {
    return 'unknown'
  }
  
  return sanitized.substring(0, 255) // Limit length
}

// Validate file type using magic numbers
function validateFileType(buffer: Buffer, expectedType: string): boolean {
  if (!buffer || buffer.length < 4) {
    return false
  }
  
  const signatures = ALLOWED_FILE_SIGNATURES[expectedType as keyof typeof ALLOWED_FILE_SIGNATURES]
  if (!signatures || signatures.length === 0) {
    // For text files like YAML, we can't rely on magic numbers
    return expectedType === 'yml' || expectedType === 'yaml'
  }
  
  const fileHeader = buffer.subarray(0, 8).toString('hex')
  return signatures.some(signature => fileHeader.startsWith(signature))
}

// Check if path is safe (no directory traversal)
function isSafePath(filePath: string, baseDir: string): boolean {
  const resolvedPath = path.resolve(baseDir, filePath)
  const resolvedBaseDir = path.resolve(baseDir)
  return resolvedPath.startsWith(resolvedBaseDir)
}

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const sanitizedFilename = sanitizeFileName(file.originalname.toLowerCase())
      
      // Validate file type
      if (!validateFileType(buffer, 'zip')) {
        return res.status(400).json({ error: 'Invalid ZIP file format' })
      }
      
      // Check file size
      if (buffer.length > MAX_FILE_SIZES.zip) {
        return res.status(413).json({ error: 'File too large' })
      }
      
      const tempFile = path.join(os.tmpdir(), `upload_${crypto.randomUUID()}_${sanitizedFilename}`)
      
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { 
          fs.unlink(tempFile, () => {}) // Clean up
          return next(err) 
        }
        
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { 
            fs.close(fd, () => {})
            fs.unlink(tempFile, () => {}) // Clean up
            return next(err) 
          }
          
          fs.close(fd, function () {
            const uploadDir = path.resolve('uploads/complaints/')
            let extractedFiles = 0
            const maxFiles = 100 // Prevent zip bombs
            
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                extractedFiles++
                
                if (extractedFiles > maxFiles) {
                  entry.autodrain()
                  return
                }
                
                const fileName = sanitizeFileName(entry.path)
                const absolutePath = path.resolve(uploadDir, fileName)
                
                // Prevent path traversal
                if (!isSafePath(fileName, uploadDir)) {
                  entry.autodrain()
                  return
                }
                
                // Challenge logic (maintained for compatibility)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { 
                  return absolutePath === path.resolve('ftp/legal.md') 
                })
                
                // Only allow files within the uploads directory
                if (absolutePath.startsWith(uploadDir)) {
                  const writeStream = fs.createWriteStream(absolutePath)
                    .on('error', function (err) { 
                      entry.autodrain()
                      next(err) 
                    })
                  
                  entry.pipe(writeStream)
                } else {
                  entry.autodrain()
                }
              })
              .on('error', function (err: unknown) { 
                fs.unlink(tempFile, () => {}) // Clean up
                next(err) 
              })
              .on('close', function () {
                fs.unlink(tempFile, () => {}) // Clean up temp file
              })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    const fileType = file.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
    const maxSize = MAX_FILE_SIZES[fileType as keyof typeof MAX_FILE_SIZES] || 1024 * 1024 // 1MB default
    
    if (file.size > maxSize) {
      return res.status(413).json({ error: 'File too large' })
    }
    
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  if (!file) {
    return next()
  }
  
  const fileType = file.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  const allowedTypes = ['pdf', 'xml', 'zip', 'yml', 'yaml']
  
  // Check file extension
  if (!allowedTypes.includes(fileType)) {
    challengeUtils.solveIf(challenges.uploadTypeChallenge, () => true)
    return res.status(400).json({ error: 'File type not allowed' })
  }
  
  // Validate file content matches extension (except for text files)
  if (file.buffer && fileType !== 'yml' && fileType !== 'yaml') {
    if (!validateFileType(file.buffer, fileType)) {
      return res.status(400).json({ error: 'File content does not match extension' })
    }
  }
  
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !allowedTypes.includes(fileType)
  })
  
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString('utf8', 0, Math.min(file.buffer.length, 1024 * 1024)) // Limit to 1MB
      
      try {
        // Secure XML parsing - disable external entities and DTD processing
        const xmlDoc = libxml.parseXml(data, {
          noblanks: true,
          noent: false,    // Disable entity processing
          nocdata: true,
          nonet: true,     // Disable network access
          dtdload: false,  // Disable DTD loading
          dtdattr: false,  // Disable DTD attribute processing
          dtdvalid: false, // Disable DTD validation
          recover: false   // Don't try to recover from errors
        })
        
        const xmlString = xmlDoc.toString(false)
        
        // Challenge logic (maintained but secured)
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { 
          return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) 
        })
        
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + sanitizeFileName(file.originalname) + ')'))
      } catch (err: any) {
        if (utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + sanitizeFileName(file.originalname) + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + sanitizeFileName(file?.originalname || 'unknown') + ')'))
    }
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString('utf8', 0, Math.min(file.buffer.length, 1024 * 1024)) // Limit to 1MB
      
      try {
        // Secure YAML parsing with safe load
        const yamlData = yaml.load(data, {
          schema: yaml.CORE_SCHEMA, // Use safe schema
          json: true,               // Only allow JSON-compatible types
          onWarning: () => {},      // Suppress warnings
          filename: sanitizeFileName(file.originalname)
        })
        
        const yamlString = JSON.stringify(yamlData)
        
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + sanitizeFileName(file.originalname) + ')'))
      } catch (err: any) {
        if (utils.contains(err.message, 'Invalid string length') || utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + sanitizeFileName(file.originalname) + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + sanitizeFileName(file?.originalname || 'unknown') + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}