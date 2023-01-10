import { Domain, Utils, BackendTypes, DBModels } from '@ikomida/shared-backend'
import { Validations } from '@ikomida/shared-logics'
import { Classes, Types } from '@ikomida/shared-types'

export default class Addresses {
  logger
  constructor(logger: Utils.Logger) {
    this.logger = logger
  }

  async newAddress(identity: Classes.CUser, input: any) {
    try {
      const payload: Classes.CAddress = Classes.CAddress.fromObject(input)
      if (!payload.validate()) {
        const error = new Utils.iKomidaError(
          Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_NEW_ADDRESS_INVALID_ADDRESS
        )
        return error.logAndReturn(this.logger)
      }

      const addressModelsResponse = await this.getAddressModels(identity)
      if ('success' in addressModelsResponse) {
        return addressModelsResponse
      }
      const userModel = addressModelsResponse.userModel
      const contractModel = addressModelsResponse.contractModel
      const addressModels = addressModelsResponse.addressModels ?? []
      for (const addressModel of addressModels) {
        await addressModel.update({
          selected: false
        })
      }
      const calcDistanceResponse = await Utils.GoogleAdmin.calcDistance(contractModel.addresses?.[0], payload)
      if (!calcDistanceResponse) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_NEW_ADDRESS_EXCEPTION)
        return error.logAndReturn(this.logger)
      }
      const [distance, duration] = calcDistanceResponse as number[]

      const location: Classes.CLocation = await Utils.GoogleAdmin.getGeocoding(payload)
      await userModel.$create('address', {
        kind: Types.TAddress.RESIDENTIAL,
        role: identity.role,
        postalCode: payload.postalCode,
        street: payload.street,
        reference: payload.reference,
        number: payload.number,
        complement: payload.complement,
        neighborhood: payload.neighborhood,
        city: payload.city,
        distance,
        duration,
        stat: payload.stat,
        coordinates: BackendTypes.CGeometry.init(BackendTypes.TGeometry.POINT, [
          location.latitude ?? 0,
          location.longitude ?? 0
        ]).toJSON(),
        contractId: contractModel.id
      })
      return await this.getAddresses(identity)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_NEW_ADDRESS_EXCEPTION,
        exception
      )
      return error.logAndReturn(this.logger)
    }
  }

  async updateAddress(identity: Classes.CUser, id?: string) {
    try {
      if (!Validations.validateUUID(id)) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_ADDRESS_MISSING_DATA)
        return error.logAndReturn(this.logger)
      }
      const addressModelsResponse = await this.getAddressModels(identity)
      if ('success' in addressModelsResponse) {
        return addressModelsResponse
      }
      const addressModels = addressModelsResponse.addressModels ?? []
      for (const addressModel of addressModels) {
        const selected = addressModel?.id === id
        await addressModel.update({
          selected
        })
      }
      return new Classes.Return(true)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_UPDATE_ADDRESS_EXCEPTION, exception)
      return error.logAndReturn(this.logger)
    }
  }

  async removeAddress(identity: Classes.CUser, id?: string) {
    try {
      if (!Validations.validateUUID(id)) {
        const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_REMOVE_ADDRESS_MISSING_DATA)
        return error.logAndReturn(this.logger)
      }
      const addressModelsResponse = await this.getAddressModels(identity)
      if ('success' in addressModelsResponse) {
        return addressModelsResponse
      }
      const addressModels = addressModelsResponse.addressModels ?? []
      for (const addressModel of addressModels) {
        if (addressModel?.id === id) {
          await addressModel.destroy()
        }
      }
      return new Classes.Return(true)
    } catch (exception: any) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_REMOVE_ADDRESS_EXCEPTION, exception)
      return error.logAndReturn(this.logger)
    }
  }

  async getAddresses(identity: Classes.CUser) {
    const addressModelsResponse = await this.getAddressModels(identity)
    if ('success' in addressModelsResponse) {
      return addressModelsResponse
    }
    const addressModels = addressModelsResponse.addressModels
    const addresses = addressModels?.map(addressModel => {
      return Classes.CAddress.init(
        addressModel.postalCode ?? '-',
        addressModel.street ?? '-',
        addressModel.neighborhood ?? '-',
        addressModel.city ?? '-',
        addressModel.stat ?? '-',
        addressModel.number,
        addressModel.complement,
        addressModel.kind,
        addressModel.reference,
        addressModel?.distance,
        addressModel?.duration,
        addressModel?.selected,
        Classes.CLocation.fromObject({
          latitude: addressModel?.coordinates?.coordinates?.[0],
          longitude: addressModel?.coordinates?.coordinates?.[1]
        }),
        addressModel?.id
      )
    })
    return new Classes.Return(addresses !== null, addresses || [])
  }

  async getAddressModels(identity: Classes.CUser) {
    const contractModel = await DBModels.ContractModel.findOne({
      where: {
        ikomidaID: identity.ikomidaID
      },
      include: [
        {
          model: DBModels.AddressModel,
          where: {
            role: Types.TRoles.VENDOR
          },
          required: false,
          order: [['createdAt', 'DESC']],
          limit: 1
        },
        {
          model: DBModels.UserModel,
          where: {
            id: identity.id,
            role: {
              [Domain.SqlDB.Op.in]: [
                Types.TRoles.VENDOR,
                Types.TRoles.STAFF,
                Types.TRoles.CLIENT,
                Types.TRoles.ADMIN,
                Types.TRoles.RESELLER
              ]
            }
          },
          required: false,
          include: [
            {
              model: DBModels.AddressModel,
              required: false,
              order: [['createdAt', 'DESC']]
            }
          ]
        }
      ]
    })
    if (!contractModel) {
      const error = new Utils.iKomidaError(
        Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_GET_ADDRESS_INVALID_CONTRACT
      )
      return error.logAndReturn(this.logger)
    }
    const userModels = contractModel?.users
    if (!userModels || userModels.length !== 1) {
      const error = new Utils.iKomidaError(Utils.iKomidaError.IKOMIDA_USERS_SERVICE_ADDRESS_GET_ADDRESS_INVALID_USER)
      return error.logAndReturn(this.logger)
    }
    const userModel = userModels[0]
    const addressModels = userModel?.addresses
    return { contractModel, userModel, addressModels }
  }
}
