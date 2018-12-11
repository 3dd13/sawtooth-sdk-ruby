require 'digest'
require 'openssl'

require 'sawtooth/signing/secp256k1/secp256k1_utils'


# A Secp256k1 specific implementation of the abstract Context class.
# using openssl Asymmetric public key - Elliptic Curve Digital Signature Algorithm (ECDSA)
module Sawtooth
  module Signing
    module Secp256k1
      class Secp256k1Context < Sawtooth::Signing::Base::Context
        include Sawtooth::Signing::Secp256k1::Secp256k1Utils

        def initialize
        end

        def algorithm_name
          'secp256k1'
        end

        def verify(signature_hex, message, public_key)
          data_hash = OpenSSL::Digest::SHA256.digest(message)
          signature_bytes = hex_to_binary(signature_hex)

          pkey_ec_group_curve = new_pkey_ec_group_curve
          pkey_ec_group_curve.public_key = public_key.openssl_public_key_point
          pkey_ec_group_curve.dsa_verify_asn1(data_hash, signature_bytes)
        end

        def sign(message, private_key)
          data_hash = OpenSSL::Digest::SHA256.digest(message)

          pkey_ec_group_curve = new_pkey_ec_group_curve
          pkey_ec_group_curve.private_key = private_key.openssl_private_key_bn
          signature = pkey_ec_group_curve.dsa_sign_asn1(data_hash)

          binary_to_hex(signature)
        end

        def new_random_private_key
          Sawtooth::Signing::Secp256k1::Secp256k1PrivateKey.new_random
        end

        def get_public_key(private_key)
          pkey_ec_group = OpenSSL::PKey::EC::Group.new(algorithm_name)
          openssl_public_key_bn = pkey_ec_group.generator.mul(private_key.openssl_private_key_bn)

          Sawtooth::Signing::Secp256k1::Secp256k1PublicKey.new(openssl_public_key_bn)
        end
      end
    end
  end
end