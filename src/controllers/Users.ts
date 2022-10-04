import {
  Domain,
  BackendTypes,
  Utils,
  comparePassword,
  cryptPassword,
  signData,
  validateSignature,
  Logics,
  passwordGenerator,
  Types,
  DBModels,
  objHasProp
} from '@ikomida/shared-backend'
import { CompactSign, importPKCS8 } from 'jose'
import crypto from 'crypto'

const host: any = {
  development: 'https://dev.reseller.ikomida.com/',
  homologation: 'https://hmlg.reseller.ikomida.com/',
  production: 'https://reseller.ikomida.com/'
}

export default class Users {
  private logger
  private blockWindow = 30 * 60 * 1000 // bloquear por 30 minutos em milisegundos
  host

  constructor(logger: Utils.Logger) {
    this.logger = logger
    this.host = host[process.env.NODE_ENV ?? 'development']
  }

  async logOut(identity: Types.Classes.CUser) {
    try {
      const role = BackendTypes.Roles.valueOf(identity.role)
      let userModels: DBModels.UserModel[] | undefined
      if (role && [BackendTypes.Roles.CLIENT, BackendTypes.Roles.VENDOR, BackendTypes.Roles.STAFF].includes(role)) {
        const contractModel = await DBModels.ContractModel.findOne({
          where: {
            ikomidaID: identity?.ikomidaID
          },
          include: {
            model: DBModels.UserModel,
            where: {
              role: identity?.role,
              id: identity?.id
            },
            required: true,
            include: [
              {
                model: DBModels.UserInfoModel,
                required: false
              }
            ]
          }
        })
        if (!contractModel) {
          const error = new Utils.iKomidaError(
            Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_INVALID_CONTRACT
          )
          return error.logAndReturn(this.logger)
        }
        userModels = contractModel?.users
      } else {
        userModels = await DBModels.UserModel.findAll({
          where: {
            role: identity?.role,
            id: identity?.id
          },
          include: {
            model: DBModels.UserInfoModel,
            required: false
          }
        })
      }
      if (userModels?.length !== 1) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_INVALID_CONTRACT
        )
        return error.logAndReturn(this.logger)
      }
      const userModel = userModels?.[0]
      await DBModels.UserInfoModel.destroy({
        where: {
          userId: userModel?.id
        }
      })
      return new Utils.Return(true)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_EXCEPTION, exception)
      return error.logAndReturn(this.logger)
    }
  }

  private userAllowed(loginFailModel?: DBModels.LoginFailModel | null) {
    return (
      !loginFailModel?.blockDate ||
      new Date().getTime() > (loginFailModel?.blockWindow ?? 0) + loginFailModel?.blockDate?.getTime()
    )
  }

  private async handleBlock(loginFailModel?: DBModels.LoginFailModel | null) {
    await loginFailModel?.increment({ attempts: 1 })
    const error = new Utils.iKomidaError(
      Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_TOO_MANY_ATEMPTS,
      ((loginFailModel?.blockWindow ?? 0) / 60 / 1000).toFixed(0),
      (
        ((loginFailModel?.blockWindow ?? 0) + (loginFailModel?.blockDate?.getTime() ?? 0) - new Date().getTime()) /
        60 /
        1000
      ).toFixed(0)
    )
    error.setStatus(429)
    return error.logAndReturn(this.logger)
  }

  private async getUnloggedUserModels(
    role: BackendTypes.Roles | null,
    ikomidaID: string,
    options: Types.Classes.CLoginOptions,
    areaCode: string | number | undefined,
    phone: string | number | undefined,
    isLoggin = false
  ) {
    let loginFailModel
    let userModels
    let contractModel
    if (isLoggin) {
      await DBModels.LoginFailModel.destroy({
        where: {
          createdAt: {
            [Domain.SqlDB.Op.lt]: new Date(new Date().getTime() - this.blockWindow * 2)
          },
          blockDate: null
        }
      })
    }
    if (role && [BackendTypes.Roles.CLIENT, BackendTypes.Roles.VENDOR, BackendTypes.Roles.STAFF].includes(role)) {
      const rules = role === BackendTypes.Roles.VENDOR ? [BackendTypes.Roles.VENDOR, BackendTypes.Roles.STAFF] : [role]
      if (isLoggin) {
        loginFailModel = await DBModels.LoginFailModel.findOne({
          where: {
            [Domain.SqlDB.Op.or]: [
              { ip: options.ip },
              {
                ikomidaID,
                role: {
                  [Domain.SqlDB.Op.in]: rules
                },
                phone: Logics.Finances.toNumber(phone),
                areaCode: Logics.Finances.toNumber(areaCode)
              }
            ]
          }
        })
        if (!this.userAllowed(loginFailModel)) {
          return await this.handleBlock(loginFailModel)
        }
      }
      const findOne = {
        where: {
          ikomidaID
        },
        include: [
          {
            model: DBModels.UserModel,
            where: {
              role: {
                [Domain.SqlDB.Op.in]: rules
              },
              phone: Logics.Finances.toNumber(phone),
              areaCode: Logics.Finances.toNumber(areaCode)
            },
            include: [
              {
                model: DBModels.ReferralModel,
                as: 'referral',
                required: false
              },
              {
                model: DBModels.UserInfoModel,
                required: false
              }
            ],
            required: false
          }
        ]
      }
      contractModel = await DBModels.ContractModel.findOne(findOne)
      if (!contractModel) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_INVALID_CONTRACT)
        return error.logAndReturn(this.logger)
      }
      userModels = contractModel?.users
    } else {
      if (isLoggin) {
        loginFailModel = await DBModels.LoginFailModel.findOne({
          where: {
            [Domain.SqlDB.Op.or]: [
              { ip: options.ip },
              {
                role: {
                  [Domain.SqlDB.Op.in]: role
                },
                phone: Logics.Finances.toNumber(phone),
                areaCode: Logics.Finances.toNumber(areaCode)
              }
            ]
          }
        })
        if (!this.userAllowed(loginFailModel)) {
          return await this.handleBlock(loginFailModel)
        }
      }
      const where = {
        role,
        phone: Logics.Finances.toNumber(phone),
        areaCode: Logics.Finances.toNumber(areaCode)
      }
      userModels = await DBModels.UserModel.findAll({
        where,
        include: [
          {
            model: DBModels.ReferralModel,
            as: 'referral',
            required: false
          },
          {
            model: DBModels.UserInfoModel,
            required: false
          }
        ]
      })
    }
    const userModel = userModels?.[0]
    return { userModel, userModels, contractModel, loginFailModel }
  }

  private async generateAccessToken(payload: Types.Classes.CUser) {
    try {
      const algorithm = 'PS256'
      const hashAlgo = 'SHA256'
      const pkcs8 = Buffer.from(process.env.IKOMIDA_PRIVATEKEY ?? '', 'base64').toString()
      const ecPrivateKey = await importPKCS8(pkcs8, algorithm)
      const shasum = crypto.createHash(hashAlgo)
      payload.timestamp = Date.now()
      shasum.update(JSON.stringify(payload))
      const hash = shasum.digest('hex')
      payload.hash = hash
      return await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader({
          alg: algorithm,
          typ: 'JWS'
        })
        .sign(ecPrivateKey)
    } catch (error: any) {
      this.logger.error(error)
    }
    return null
  }

  async authenticateUser(
    inputRole: string,
    ikomidaID: string,
    areaCode: string | number,
    phone: string | number,
    password: string,
    options: Types.Classes.CLoginOptions
  ) {
    try {
      const role = BackendTypes.Roles.valueOf(inputRole)
      if (
        (!role || !ikomidaID) &&
        (!options.platform || !options.deviceId || !options.ip || !areaCode || !phone || !password)
      ) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_MISSING_DATA)
        return error.logAndReturn(this.logger)
      }
      const unloggedUserModels = role
        ? await this.getUnloggedUserModels(role, ikomidaID, options, areaCode, phone, true)
        : { userModel: null, userModels: null, loginFailModel: null }
      if ('success' in unloggedUserModels) {
        return unloggedUserModels
      }
      const { userModel, userModels, loginFailModel } = unloggedUserModels
      if (userModels?.length !== 1 || !userModel || !(await comparePassword(String(password), userModel.password))) {
        let message = '!'
        if (loginFailModel) {
          if (loginFailModel && (loginFailModel?.attempts ?? 0) > 5) {
            loginFailModel.attempts = (loginFailModel?.attempts ?? 0) + 1
            loginFailModel.blockDate = new Date()
            loginFailModel.blockWindow = this.blockWindow
            await loginFailModel?.save()
            message = ' O Acesso da sua conta foi bloqueado por 30 minutos!'
          } else {
            await loginFailModel.increment({ attempts: 1 })
            if ((loginFailModel?.attempts ?? 0) > 2) {
              message = ` O Acesso da sua conta será bloqueado após ${6 - (loginFailModel?.attempts ?? 0)} tentativas!`
            }
          }
        } else {
          await DBModels.LoginFailModel.create({
            ip: options.ip,
            ikomidaID,
            role: userModel?.role ?? role,
            phone: Logics.Finances.toNumber(phone),
            areaCode: Logics.Finances.toNumber(areaCode),
            attempts: 1
          })
        }
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_UNAUTHORIZED, message)
        return error.logAndReturn(this.logger)
      }
      await loginFailModel?.destroy()
      const userInfoModel = userModel?.userInfos?.[0]
      if (
        (!role || !BackendTypes.Roles.isInternal(role)) &&
        userInfoModel &&
        (!(options.platform !== null && [undefined, options.platform].includes(userInfoModel?.platform)) ||
          !(options.deviceId !== null && [undefined, options.deviceId].includes(userInfoModel?.deviceId)))
      ) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_MULTI_DEVICE)
        error.setStatus(409)
        return error.logAndReturn(this.logger)
      }
      const user = await this.createUserObject(role, ikomidaID, userModel, options?.platform ?? '-', options.deviceId)
      user.id = userModel.id

      const result = await this.generateAccessToken(user)
      await DBModels.UserInfoModel.destroy({
        where: {
          userId: userModel?.id
        }
      })
      await userModel.$create('userInfo', options)
      await userModel?.save()
      return new Utils.Return(result !== null, result)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_AUTH_EXCEPTION, exception)
      return error.logAndReturn(this.logger)
    }
  }

  async createPhoneValidation(role: BackendTypes.Roles | null, ikomidaID: string | undefined, input: any) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!Logics.Validations.validateUUID(payload.termId)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_TERM
        )
        return error.logAndReturn(this.logger)
      }
      if (!ikomidaID || role !== BackendTypes.Roles.CLIENT) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      if ((payload.name?.length ?? 0) <= 2) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_NAME
        )
        return error.logAndReturn(this.logger)
      }
      if ((payload.lastName?.length ?? 0) <= 2) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_LAST_NAME
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validateCPF(payload.identity)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_CPF
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validateEmail(payload.email)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_EMAIL
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePhone(payload.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_PHONE
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePassword(payload.password)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_PASSWORD
        )
        return error.logAndReturn(this.logger)
      }
      const contractModel = await DBModels.ContractModel.findOne({
        where: {
          ikomidaID
        }
      })
      if (!contractModel) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_INVALID_CONTRACT
        )
        return error.logAndReturn(this.logger)
      }
      const code = Logics.Finances.pad(Math.ceil(Math.random() * 10000), 4)
      payload.ikomidaID = ikomidaID
      payload.role = role.id
      payload.phoneValidationCode = code
      const signatureObject = payload.toJSON()
      delete signatureObject.signature
      const signature = await signData(signatureObject)
      const validationObject = {
        role,
        code,
        signature
      }
      const phoneValidationCodeModel = await contractModel.$create('phoneValidationCode', validationObject)
      const message = new Utils.SMS(Utils.SMS.VALIDATION_CODE, code, contractModel?.contractName ?? 'iKomida')
      const smsPayload = new Types.Classes.CAMQPPayload<Types.Classes.CAMQPPayloadObject>()
      smsPayload.method = 'send'
      smsPayload.object = new Types.Classes.CAMQPPayloadObject()
      smsPayload.object.areaCode = String(payload.areaCode)
      smsPayload.object.phone = payload.phone
      smsPayload.object.message = message
      const amqp = new Domain.RabbitMQ(this.logger)
      await amqp?.publish(Domain.RabbitMQ.SMS_QUEUE, smsPayload)
      await amqp?.close()
      if (phoneValidationCodeModel) {
        return new Utils.Return(true, signature)
      }
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_EXCEPTION,
        exception
      )
      return error.logAndReturn(this.logger)
    }
    const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_UNKNOWN)
    return error.logAndReturn(this.logger)
  }

  async validatePhoneValidationCode(role: BackendTypes.Roles | null, ikomidaID: string, input: any) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!Logics.Validations.validateUUID(payload.termId)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_TERM
        )
        return error.logAndReturn(this.logger)
      }
      if (!ikomidaID || role !== BackendTypes.Roles.CLIENT) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      if ((payload.name?.length ?? 0) <= 2) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_NAME)
        return error.logAndReturn(this.logger)
      }
      if ((payload.lastName?.length ?? 0) <= 2) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_LAST_NAME
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validateCPF(payload.identity)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_CPF
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validateEmail(payload.email)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_EMAIL
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePhone(payload.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_PHONE
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePassword(payload.password)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_PASSWORD
        )
        return error.logAndReturn(this.logger)
      }
      if (!payload.signature) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_SIGNATURE
        )
        return error.logAndReturn(this.logger)
      }
      const contractModel = await DBModels.ContractModel.findOne({
        where: {
          ikomidaID
        }
      })
      if (!contractModel) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_INVALID_CONTRACT
        )
        return error.logAndReturn(this.logger)
      }
      payload.ikomidaID = ikomidaID
      payload.role = role.id
      const signatureObject = payload.toJSON()
      delete signatureObject.signature
      if (await validateSignature(signatureObject, payload.signature)) {
        const phoneValidationCodeModels = await contractModel.$get('phoneValidationCodes', {
          where: {
            role,
            code: payload.phoneValidationCode,
            signature: payload.signature
          }
        })
        return new Utils.Return(phoneValidationCodeModels?.length === 1)
      }
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_EXCEPTION,
        exception.message
      )
      return error.logAndReturn(this.logger)
    }
    const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_UNKNOWN)
    return error.logAndReturn(this.logger)
  }

  async newUser(role: BackendTypes.Roles | null, ikomidaID: string, input: any) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!role || ![BackendTypes.Roles.CLIENT, BackendTypes.Roles.RESELLER].includes(role)) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_CONTRACT_SERVICE_INVALID_TERM_ID)
        return error.logAndReturn(this.logger)
      }
      const termModel = await DBModels.TermModel.findOne({
        where: {
          id: payload.termId
        }
      })
      if (!termModel) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_CONTRACT_SERVICE_INVALID_TERM_ID)
        return error.logAndReturn(this.logger)
      }
      const contractModel = await DBModels.ContractModel.findOne({
        where: {
          ikomidaID
        }
      })
      if (role === BackendTypes.Roles.CLIENT && !contractModel) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_INVALID_CONTRACT)
        return error.logAndReturn(this.logger)
      }
      const validatePhoneValidationCode = await this.validatePhoneValidationCode(role, ikomidaID, input)
      if (!validatePhoneValidationCode?.success) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_INVALID_PHONE_VALIDATION_CODE
        )
        return error.logAndReturn(this.logger)
      }
      const where = {
        where: {
          role,
          [Domain.SqlDB.Op.or]: [
            {
              areaCode: Logics.Finances.toNumber(payload.areaCode),
              phone: Logics.Finances.toNumber(payload.phone)
            },
            {
              identity: Logics.Finances.toNumber(payload.identity)
            },
            {
              identity: payload.email
            }
          ]
        }
      }
      const userModels =
        role === BackendTypes.Roles.CLIENT
          ? await contractModel?.$get('users', where)
          : await DBModels.UserModel.findAll(where)
      if (userModels?.length !== 0) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_ALREADY_EXIST)
        return error.logAndReturn(this.logger)
      }
      const user = await this.createUserObject(role, ikomidaID, payload)
      user.avatar = payload.avatar
      if (payload.password) {
        user.password = (await cryptPassword(payload.password)).hash
      } else {
        //TODO: -- Put corrct error code
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_ALREADY_EXIST)
        return error.logAndReturn(this.logger)
      }
      const userModel = await new DBModels.UserModel(user).save()
      if (role === BackendTypes.Roles.CLIENT) {
        await contractModel?.$add('users', userModel)
      }
      const termDetails = {
        termId: termModel?.id,
        name: termModel?.name,
        text: termModel?.text,
        type: termModel?.type,
        contract: contractModel?.id,
        user: userModel?.id
      }
      const hash = crypto.createHash('sha256').update(JSON.stringify(termDetails)).digest('base64')
      const termHashModel = await termModel?.$create('termHash', { hash })
      await userModel?.$set('termHash', termHashModel)
      if (role === BackendTypes.Roles.CLIENT) {
        await contractModel?.$add('termHashs', termHashModel)
      }

      try {
        if (userModel) {
          let emailMessage

          if (role === BackendTypes.Roles.CLIENT) {
            emailMessage = new Utils.Email(
              Utils.Email.CLIENT_REGISTRATION_SUCCESSFULL,
              contractModel?.contractName ?? 'iKomida',
              userModel?.name,
              contractModel?.contractName ?? 'iKomida'
            )
          } else {
            emailMessage = new Utils.Email(
              Utils.Email.RESELLER_REGISTRATION_SUCCESSFULL,
              'iKomida vendedor',
              userModel?.name,
              `${this.host}apps`,
              userModel?.phone,
              '',
              'iKomida',
              this.host
            )
          }
          const emailPayload = new Types.Classes.CAMQPPayload<Types.Classes.CAMQPPayloadObject>()
          emailPayload.method = 'send'
          const payloadObject: Types.Classes.CAMQPPayloadObject = Types.Classes.CAMQPPayloadObject.fromObject({
            from: {
              email: `no-replay@ikomida.com`,
              name: `iKomida`
            },
            to: {
              email: userModel?.email,
              name: `${userModel?.name} ${userModel?.lastName}`
            },
            message: emailMessage
          })
          emailPayload.object = payloadObject
          const amqp = new Domain.RabbitMQ(this.logger)
          await amqp?.publish(Domain.RabbitMQ.EMAIL_QUEUE, emailPayload)
          await amqp?.close()
        }
      } catch (exception: any) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_EXCEPTION, exception)
        error.log(this.logger)
      }
    } catch (exception: any) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_EXCEPTION, exception)
      return error.logAndReturn(this.logger)
    }
    return new Utils.Return(true)
  }

  async createPasswordPhoneValidation(
    role: BackendTypes.Roles | null,
    ikomidaID: string | undefined,
    input: any,
    options: Types.Classes.CLoginOptions
  ) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!role || !ikomidaID) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePhone(payload.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_MISSING_PHONE
        )
        return error.logAndReturn(this.logger)
      }
      if (Utils.System.isDemo(ikomidaID, payload.areaCode, payload.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      const unloggedUserModels = await this.getUnloggedUserModels(
        role,
        ikomidaID,
        options,
        payload.areaCode,
        payload.phone
      )
      if ('success' in unloggedUserModels) {
        return unloggedUserModels
      }
      const { userModel, userModels, contractModel } = unloggedUserModels
      if (userModels?.length !== 1) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_INVALID_CONTRACT
        )
        return error.logAndReturn(this.logger)
      }
      const code = Logics.Finances.pad(Math.ceil(Math.random() * 10000), 4)
      payload.id = userModel?.id
      payload.ikomidaID = ikomidaID
      payload.role = role.id
      payload.phoneValidationCode = code
      const signatureObject = payload.toJSON()
      delete signatureObject.signature
      const signature = await signData(signatureObject)
      const validationObject = {
        role,
        code,
        signature
      }
      const phoneValidationCodeModel = await userModel?.$create('phoneValidationCode', validationObject)
      const message = new Utils.SMS(Utils.SMS.VALIDATION_CODE, code, contractModel?.contractName ?? 'iKomida')
      const smsPayload = new Types.Classes.CAMQPPayload<Types.Classes.CAMQPPayloadObject>()
      smsPayload.method = 'send'
      smsPayload.object = new Types.Classes.CAMQPPayloadObject()
      smsPayload.object.areaCode = String(payload.areaCode)
      smsPayload.object.phone = payload.phone
      smsPayload.object.message = message
      const amqp = new Domain.RabbitMQ(this.logger)
      await amqp?.publish(Domain.RabbitMQ.SMS_QUEUE, smsPayload)
      await amqp?.close()
      if (phoneValidationCodeModel) {
        return new Utils.Return(true, signature)
      }
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_EXCEPTION,
        exception
      )
      return error.logAndReturn(this.logger)
    }
    const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_UNKNOWN)
    return error.logAndReturn(this.logger)
  }

  async validatePasswordPhoneValidationCode(
    role: BackendTypes.Roles | null,
    ikomidaID: string | undefined,
    input: any,
    options: Types.Classes.CLoginOptions,
    internal = false
  ) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!role || !ikomidaID) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePhone(payload.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_PHONE
        )
        return error.logAndReturn(this.logger)
      }
      if (!payload.signature) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_MISSING_SIGNATURE
        )
        return error.logAndReturn(this.logger)
      }
      if (Utils.System.isDemo(ikomidaID, payload.areaCode, payload.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      const unloggedUserModels = await this.getUnloggedUserModels(
        role,
        ikomidaID,
        options,
        payload.areaCode,
        payload.phone
      )
      if ('success' in unloggedUserModels) {
        return unloggedUserModels
      }
      const { userModel, userModels } = unloggedUserModels
      if (userModels?.length !== 1) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_INVALID_CONTRACT
        )
        return error.logAndReturn(this.logger)
      }
      const phoneValidationCodeModels = await userModel?.$get('phoneValidationCodes', {
        where: {
          role,
          code: payload.phoneValidationCode,
          signature: payload.signature
        }
      })
      if (phoneValidationCodeModels?.length !== 1) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_INVALID_CONTRACT
        )
        return error.logAndReturn(this.logger)
      }
      payload.id = userModel?.id
      payload.ikomidaID = ikomidaID
      payload.role = role.id
      const signatureObject = payload.toJSON()
      delete signatureObject.signature
      if (await validateSignature(signatureObject, payload.signature)) {
        if (internal) {
          return unloggedUserModels
        }
        return new Utils.Return(true)
      }
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_EXCEPTION,
        exception.message
      )
      return error.logAndReturn(this.logger)
    }
    const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_VALIDATE_PHONE_VALIDATION_UNKNOWN)
    return error.logAndReturn(this.logger)
  }

  async requestPassword(role: any, ikomidaID: string, input: any, options: any) {
    try {
      const validatePasswordPhoneValidationCode = await this.validatePasswordPhoneValidationCode(
        role,
        ikomidaID,
        input,
        options,
        true
      )
      if ('success' in validatePasswordPhoneValidationCode) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_INVALID_PHONE_VALIDATION_CODE
        )
        return error.logAndReturn(this.logger)
      }
      const { userModel, contractModel } = validatePasswordPhoneValidationCode
      const newPassword = passwordGenerator(8)
      if (userModel) {
        userModel.password = (await cryptPassword(newPassword)).hash
        await userModel?.save()
      }
      const emailMessage = new Utils.Email(
        Utils.Email.CLIENT_PASSWORD_REQUESTED_SUCCESSFULL,
        contractModel?.contractName ?? 'iKomida',
        userModel?.name,
        newPassword,
        contractModel?.contractName ?? 'iKomida'
      )

      const emailPayload = new Types.Classes.CAMQPPayload<Types.Classes.CAMQPPayloadObject>()
      emailPayload.method = 'send'
      const payloadObject: Types.Classes.CAMQPPayloadObject = Types.Classes.CAMQPPayloadObject.fromObject({
        from: {
          email: `no-replay@ikomida.com`,
          name: `iKomida`
        },
        to: {
          email: userModel?.email,
          name: `${userModel?.name} ${userModel?.lastName}`
        },
        message: emailMessage
      })
      emailPayload.object = payloadObject
      const amqp = new Domain.RabbitMQ(this.logger)
      await amqp?.publish(Domain.RabbitMQ.EMAIL_QUEUE, emailPayload)
      await amqp?.close()
      return new Utils.Return(true)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_NEW_USER_EXCEPTION, exception)
      return error.logAndReturn(this.logger)
    }
  }

  private async createUserObject(
    role: BackendTypes.Roles | null,
    ikomidaID: string,
    payload: DBModels.UserModel | Types.Classes.CUser,
    platform?: string,
    deviceId?: string
  ) {
    let userRole = payload.role ?? role
    userRole =
      userRole && BackendTypes.Roles.isInstance(userRole) ? (userRole as BackendTypes.Roles).id : String(userRole)
    const userObject = Types.Classes.CUser.init(
      userRole,
      payload.name ?? '-',
      payload.lastName ?? '-',
      payload.identity ?? '-',
      payload.email ?? '-',
      payload.phone ?? '-',
      String(payload.areaCode),
      ''
    )
    if (platform) {
      userObject.platform = platform
    }
    if (deviceId && deviceId !== undefined && deviceId !== null && deviceId !== '') {
      userObject.deviceId = deviceId
    }
    if (ikomidaID) {
      userObject.ikomidaID = ikomidaID
    }
    try {
      if (payload.role === BackendTypes.Roles.RESELLER && payload instanceof DBModels.UserModel) {
        userObject.referralCode = payload.referral?.code
      }
    } catch (exception: any) {
      new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_CREATE_USER_OBJECT_EXCEPTION, exception).log(
        this.logger
      )
    }
    return userObject
  }

  async getUsersCount(identity: Types.Classes.CUser) {
    const role = BackendTypes.Roles.valueOf(identity.role)
    if (!role || ![BackendTypes.Roles.VENDOR, BackendTypes.Roles.STAFF].includes(role)) {
      return new Utils.Return(false, 0)
    }
    const contractModel = await DBModels.ContractModel.findOne({
      where: {
        ikomidaID: identity.ikomidaID
      },
      include: [
        {
          model: DBModels.UserModel,
          where: {
            id: identity.id,
            role: {
              [Domain.SqlDB.Op.in]: [BackendTypes.Roles.VENDOR, BackendTypes.Roles.STAFF, BackendTypes.Roles.ADMIN]
            }
          },
          required: true
        }
      ]
    })
    if (!contractModel) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_USERS_SERVICE_USERS_GET_USER_COUNT_INVALID_CONTRACT
      )
      return error.logAndReturn(this.logger)
    }
    const userModels = await contractModel.$get('users', {
      where: {
        role: BackendTypes.Roles.CLIENT
      }
    })
    return new Utils.Return(true, userModels.length)
  }

  async updatePassword(identity: Types.Classes.CUser, input: any) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!this.validateUpdatePassword(payload)) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_MISSING_DATA)
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePassword(payload.oldPass)) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_PASSWORD)
        return error.logAndReturn(this.logger)
      }
      if (!Logics.Validations.validatePassword(payload.newPass)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_NEW_PASSWORD
        )
        return error.logAndReturn(this.logger)
      }
      if (payload.newPass !== payload.reNewPass) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_RE_NEW_PASSWORD
        )
        return error.logAndReturn(this.logger)
      }
      let userModels: DBModels.UserModel[] | undefined
      let contractModel
      const role = BackendTypes.Roles.valueOf(identity.role)
      if (
        !role ||
        ![BackendTypes.Roles.ADMIN, BackendTypes.Roles.RESELLER, BackendTypes.Roles.MANAGER].includes(role)
      ) {
        contractModel = await DBModels.ContractModel.findOne({
          where: {
            ikomidaID: identity.ikomidaID
          },
          include: [
            {
              model: DBModels.UserModel,
              where: {
                role: identity.role,
                id: identity.id
              },
              required: true
            }
          ]
        })
        if (!contractModel) {
          const error = new Utils.iKomidaError(
            Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_CONTRACT
          )
          return error.logAndReturn(this.logger)
        }
        userModels = contractModel.users
      } else {
        userModels = await DBModels.UserModel.findAll({
          where: {
            role: identity.role,
            id: identity.id
          }
        })
      }
      if (userModels?.length !== 1) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_USER)
        return error.logAndReturn(this.logger)
      }
      const userModel = userModels?.[0]
      if (Utils.System.isDemo(contractModel?.ikomidaID, userModel?.areaCode, userModel?.phone)) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION
        )
        return error.logAndReturn(this.logger)
      }
      if (!(await comparePassword(String(payload.oldPass), userModel?.password))) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_AUTH_UNAUTHORIZED)
        return error.logAndReturn(this.logger)
      }
      if (userModel) {
        userModel.password = (await cryptPassword(payload.newPass)).hash
      }
      await userModel?.save()
      try {
        const emailMessage = new Utils.Email(
          Utils.Email.CLIENT_PASSWORD_UPDATED_SUCCESSFULL,
          contractModel?.contractName ?? 'iKomida',
          userModel?.name,
          contractModel?.contractName ?? 'iKomida'
        )
        const emailPayload = new Types.Classes.CAMQPPayload<Types.Classes.CAMQPPayloadObject>()
        emailPayload.method = 'send'
        const payloadObject: Types.Classes.CAMQPPayloadObject = Types.Classes.CAMQPPayloadObject.fromObject({
          from: {
            email: `no-replay@ikomida.com`,
            name: `iKomida`
          },
          to: {
            email: userModel?.email,
            name: `${userModel?.name} ${userModel?.lastName}`
          },
          message: emailMessage
        })
        emailPayload.object = payloadObject
        const amqp = new Domain.RabbitMQ(this.logger)
        await amqp?.publish(Domain.RabbitMQ.EMAIL_QUEUE, emailPayload)
        await amqp?.close()
      } catch (exception: any) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_EXCEPTION,
          exception
        )
        error.log(this.logger)
      }
      return new Utils.Return(true)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_EXCEPTION,
        exception
      )
      return error.logAndReturn(this.logger)
    }
  }

  async getSettings(ikomidaID: string) {
    const contractModel = await DBModels.ContractModel.findOne({
      where: {
        ikomidaID
      },
      include: [
        {
          model: DBModels.AddressModel,
          where: {
            role: BackendTypes.Roles.VENDOR
          },
          required: false,
          order: [['createdAt', 'DESC']],
          limit: 1
        },
        {
          model: DBModels.VendorSettingsModel,
          required: true
        },
        {
          model: DBModels.ContractPaymentSignatureModel,
          required: false
        }
      ]
    })
    if (!contractModel) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_GET_SETTINGS_INVALID_CONTRACT)
      return error.logAndReturn(this.logger)
    }
    const vendorSettingsModel = contractModel?.vendorSettings
    if (!vendorSettingsModel) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_GET_SETTINGS_EMPTY)
      return error.logAndReturn(this.logger)
    }
    const addressModel = contractModel?.addresses?.[0]
    const isActive =
      contractModel?.active &&
      contractModel?.contractPaymentSignature?.status === Types.Types.TAsaasSignatureStatus.ACTIVE
    const payload: Types.Classes.CVendorSettings = Types.Classes.CVendorSettings.fromObject({
      profile: Types.Classes.CVendorProfile.init(
        vendorSettingsModel?.areaCode ?? 0,
        vendorSettingsModel?.contractName ?? '',
        contractModel?.contractIdentity ?? '',
        '',
        vendorSettingsModel?.phone ?? '',
        vendorSettingsModel?.email ?? '',
        Types.Classes.CAddress.init(
          addressModel?.postalCode ?? '',
          addressModel?.street ?? '',
          addressModel?.neighborhood ?? '',
          addressModel?.city ?? '',
          addressModel?.stat ?? '',
          addressModel?.number ?? '',
          addressModel?.complement ?? '',
          addressModel?.kind,
          addressModel?.reference
        ),
        vendorSettingsModel?.restaurantImage
      ),
      business: Types.Classes.CBusinessTime.fromObject({
        hours: Types.Classes.CBusinessTimeHours.fromObject(vendorSettingsModel?.businessHours),
        days: vendorSettingsModel?.businessDays
      }),
      delivery: Types.Classes.CVendorDelivery.init(
        vendorSettingsModel?.deliveryFree ?? false,
        vendorSettingsModel?.delivery ?? 0,
        vendorSettingsModel?.deliveryMin ?? 0
      ),
      preparation: Types.Classes.CVendorPreparation.init(
        vendorSettingsModel?.preparationMin ?? 0,
        vendorSettingsModel?.preparationMax ?? 0
      ),
      isActive
    })
    return new Utils.Return(true, payload)
  }

  validateUpdatePassword(payload: any) {
    return objHasProp(['oldPass', 'newPass', 'reNewPass'], payload)
  }
}
