import express from 'express'
import bodyParser from 'body-parser'
import Addresses from './controllers/Addresses.js'
import Users from './controllers/Users.js'
import Profiles from './controllers/Profiles.js'
import { BackendTypes, Utils } from '@ikomida/shared-backend'

import { createRequire } from 'module'
import { Types } from '@ikomida/shared-backend'
import { IncomingHttpHeaders } from 'http'
const require = createRequire(import.meta.url)
let { name } = require('../package.json')
name = name
  .replace(/^(@\S+\/)?(svelte-)?(\S+)/, '$3')
  .replace(/^\w/, (m: string) => m.toUpperCase())
  .replace(/-\w/g, (m: string[]) => m[1].toUpperCase())
const logger = Utils.Logger.getInstance(name)

const app = express()
app.disable('x-powered-by')
app.use(bodyParser.json({ limit: '10mb' }))
Utils.System.setExpressResponse(app)
const port = process?.env?.PORT || 80
const addresses = new Addresses(logger)
const users = new Users(logger)
const profiles = new Profiles(logger)

app.get('/addresses', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await addresses.getAddresses(identity)
  res.sendResponse(payload)
})

app.get('/settings', async (req, res) => {
  const payload = await users.getSettings(String(req.headers?.['x-ikomida-id']))
  res.sendResponse(payload)
})

app.get('/usersCount', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await users.getUsersCount(identity)
  res.sendResponse(payload)
})

app.post('/address', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await addresses.newAddress(identity, req.body)
  res.sendResponse(payload)
})

app.put('/address/:id', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await addresses.updateAddress(identity, req?.params?.id)
  res.sendResponse(payload)
})

app.delete('/address/:id', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await addresses.removeAddress(identity, req?.params?.id)
  res.sendResponse(payload)
})

app.patch('/profile/avatar', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await profiles.updateAvatar(identity, req?.body)
  res.sendResponse(payload)
})

app.get('/profile', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await profiles.profile(identity)
  res.sendResponse(payload)
})

app.post('/password', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await users.updatePassword(identity, req.body)
  res.status(payload?.success ? 201 : 400).sendResponse(payload)
})

app.post('/auth', async (req, res) => {
  const payload = await users.authenticateUser(
    String(req.headers?.['x-ikomida-agent']),
    String(req.headers?.['x-ikomida-id']),
    req.body?.areaCode,
    req.body?.phone,
    req.body?.password,
    options(req.headers)
  )
  res.status(payload?.success ? 201 : 403).sendResponse(payload)
})

app.delete('/deleteAccount', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await users.deleteAccount(identity)
  res.status(payload?.success ? 201 : 403).sendResponse(payload)
})

app.delete('/logout', async (req, res) => {
  const identity: Types.Classes.CUser = Types.Classes.CUser.fromObject(req.headers?.identity)
  const payload = await users.logOut(identity)
  res.status(payload?.success ? 201 : 403).sendResponse(payload)
})

app.post('/requestPhoneValidation', async (req, res) => {
  const payload = await users.createPhoneValidation(
    Types.Types.TRoles.valueOf(String(req.headers?.['x-ikomida-agent'])),
    String(req.headers?.['x-ikomida-id']),
    req.body
  )
  res.status(payload?.success ? 201 : 400).sendResponse(payload)
})

app.post('/validatePhoneValidationCode', async (req, res) => {
  const payload = await users.validatePhoneValidationCode(
    Types.Types.TRoles.valueOf(String(req.headers?.['x-ikomida-agent'])),
    String(req.headers?.['x-ikomida-id']),
    req.body
  )
  res.status(payload?.success ? 200 : 400).sendResponse(payload)
})

app.post('/subscribe', async (req, res) => {
  const payload = await users.newUser(
    Types.Types.TRoles.valueOf(String(req.headers?.['x-ikomida-agent'])),
    String(req.headers?.['x-ikomida-id']),
    req.body,
    options(req.headers)
  )
  res.status(payload?.success ? 201 : 400).sendResponse(payload)
})

app.post('/requestPasswordPhoneValidation', async (req, res) => {
  const payload = await users.createPasswordPhoneValidation(
    Types.Types.TRoles.valueOf(String(req.headers?.['x-ikomida-agent'])),
    String(req.headers?.['x-ikomida-id']),
    req.body,
    options(req.headers)
  )
  res.status(payload?.success ? 201 : 400).sendResponse(payload)
})

app.post('/validatePasswordPhoneValidationCode', async (req, res) => {
  const payload = (await users.validatePasswordPhoneValidationCode(
    Types.Types.TRoles.valueOf(String(req.headers?.['x-ikomida-agent'])),
    String(req.headers?.['x-ikomida-id']),
    req.body,
    options(req.headers)
  )) as Classes.Return<any>
  res.status(payload?.success ? 200 : 400).sendResponse(payload)
})

app.post('/requestPassword', async (req, res) => {
  const payload = await users.requestPassword(
    Types.Types.TRoles.valueOf(String(req.headers?.['x-ikomida-agent'])),
    String(req.headers?.['x-ikomida-id']),
    req.body,
    options(req.headers)
  )
  res.status(payload?.success ? 201 : 400).sendResponse(payload)
})

app.all('/', async (req, res) => {
  res.status(200).send()
})

app.all('*', async (req, res) => {
  logger.error(`Users endpoint "${req?.url}" not found:`)
  res.status(404).sendResponse({ error: 'NOT FOUND' })
})

app.listen(port, () => {
  logger.info(`${name} listening at http://localhost:${port}`)
})

function options(headers: IncomingHttpHeaders) {
  return Types.Classes.CLoginOptions.init(
    String(headers?.['x-client-ipaddress']),
    String(headers?.['x-forwarded-for']),
    String(headers?.['x-ikomida-plateform']),
    String(headers?.['x-ikomida-did']),
    String(headers?.['x-client-region']),
    String(headers?.['x-client-subregion']),
    String(headers?.['x-client-citylatlong']),
    String(headers?.['x-client-city']),
    String(headers?.['x-requested-with'])
  )
}
