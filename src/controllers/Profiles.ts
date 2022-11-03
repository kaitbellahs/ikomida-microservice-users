import { Utils, Types, BackendTypes, DBModels } from '@ikomida/shared-backend'
import { IiKomidaErrorModel } from '@ikomida/shared-backend/lib/src/Utils/iKomidaError'

export default class Profiles {
  private IKOMIDA_USERS_SERVICE_PROFILE_UPDATE_AVATAR_INVALID_AVATAR: IiKomidaErrorModel = {
    code: 'IMU001',
    message: 'Houve algum problema na transferência da foto do seu perfil'
  }
  private logger
  private googleAdmin
  constructor(logger: Utils.Logger) {
    this.logger = logger
    this.googleAdmin = new Utils.GoogleAdmin(this.logger)
  }

  async updateAvatar(identity: Types.Classes.CUser, input: any) {
    try {
      const payload: Types.Classes.CUser = Types.Classes.CUser.fromObject(input)
      if (!payload.avatar) {
        const error = new Utils.iKomidaError(this.IKOMIDA_USERS_SERVICE_PROFILE_UPDATE_AVATAR_INVALID_AVATAR)
        return error.logAndReturn(this.logger)
      }

      let userModels: DBModels.UserModel[] | undefined
      let contractModel
      const role = BackendTypes.Roles.valueOf(identity.role)
      if (!role || (role !== BackendTypes.Roles.RESELLER && !BackendTypes.Roles.isInternal(role))) {
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
          throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_CONTRACT)
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
        throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_USER)
      }
      const userModel = userModels?.[0]
      if (Utils.System.isDemo(contractModel?.ikomidaID, userModel?.areaCode, userModel?.phone)) {
        throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION)
      }
      if (!userModel || !userModel.id) {
        throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_USER)
      }
      userModel.avatar = await this.googleAdmin.uploadToStorage(
        identity,
        userModel.id,
        'image',
        'userProfile',
        payload.avatar,
        userModel.avatar
      )
      await userModel?.save()
      return new Utils.Return(true)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_NEW_ADDRESS_EXCEPTION,
        exception
      )
      return error.logAndReturn(this.logger)
    }
  }

  async profile(identity: Types.Classes.CUser) {
    try {
      let userModels: DBModels.UserModel[] | undefined
      let contractModel
      const role = BackendTypes.Roles.valueOf(identity.role)
      if (!role || (role !== BackendTypes.Roles.RESELLER && !BackendTypes.Roles.isInternal(role))) {
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
              required: true,
              include: [
                {
                  model: DBModels.AddressModel,
                  where: {
                    selected: true
                  },
                  required: false
                }
              ]
            }
          ]
        })
        if (!contractModel) {
          throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_CONTRACT)
        }
        userModels = contractModel.users
      } else {
        userModels = await DBModels.UserModel.findAll({
          where: {
            role: identity.role,
            id: identity.id
          },
          include: [
            {
              model: DBModels.AddressModel,
              where: {
                selected: true
              },
              required: false
            }
          ]
        })
      }
      if (userModels?.length !== 1) {
        throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_USER)
      }
      const userModel = userModels?.[0]
      if (Utils.System.isDemo(contractModel?.ikomidaID, userModel?.areaCode, userModel?.phone)) {
        throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_GATEWAY_SERVICE_CREATE_PHONE_VALIDATION_AUTHENTICATION)
      }
      if (!userModel || !userModel.id) {
        throw new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_PASSWORD_INVALID_USER)
      }
      const address = userModel.addresses?.[0]
      const user = Types.Classes.CUser.init(
        userModel.role?.id ?? '-',
        userModel.name ?? '-',
        userModel.lastName ?? '-',
        userModel.identity ?? '-',
        userModel.email ?? '-',
        userModel.phone ?? '-',
        String(userModel.areaCode),
        '',
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        Types.Classes.CAddress.init(
          address?.postalCode ?? '-',
          address?.street ?? '-',
          address?.neighborhood ?? '-',
          address?.city ?? '-',
          address?.stat ?? '-',
          address?.number,
          address?.complement,
          address?.kind,
          address?.reference
        ),
        undefined,
        undefined,
        userModel.avatar,
        undefined,
        userModel.referral?.code
      )
      return new Utils.Return(true, user)
    } catch (exception: any) {
      let error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_NEW_ADDRESS_EXCEPTION,
        exception
      )
      if (exception instanceof Utils.iKomidaError) {
        error = exception
      }
      return error.logAndReturn(this.logger)
    }
  }
}
