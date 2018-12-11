require 'openssl'

require 'sawtooth/signing/base/private_key'
require 'sawtooth/signing/secp256k1/secp256k1_utils'

module Sawtooth
  module Signing
    module Secp256k1
      class Secp256k1PrivateKey < Sawtooth::Signing::Base::PrivateKey
        include Sawtooth::Signing::Secp256k1::Secp256k1Utils

        ALGORITHM_NAME = 'secp256k1'

        attr_accessor :openssl_private_key_bn

        def initialize(openssl_private_key_bn)
          @openssl_private_key_bn = openssl_private_key_bn
        end

        def algorithm_name
          ALGORITHM_NAME
        end

        # Return the private key encoded as a hex string.
        def as_hex
          @openssl_private_key_bn.to_s(16).downcase
        end

        # Return the private key bytes.
        def as_bytes
          hex_to_binary(as_hex)
        end

        # Create Private Key instance From Hex
        def self.from_hex(hex_str)
          openssl_private_key_bn = OpenSSL::BN.new(hex_str, 16)
          check_key!(openssl_private_key_bn)
          self.new(openssl_private_key_bn)
        end

        def self.from_bytes(byte_str)
          from_hex(binary_to_hex(byte_str))
        end

        def self.new_random
          pkey_ec_group_curve = new_pkey_ec_group_curve
          pkey_ec_group_curve.generate_key
          openssl_private_key_bn = pkey_ec_group_curve.private_key
          self.new(openssl_private_key_bn)
        end

        private

        def new_pkey_ec_group_curve
          pkey_ec_group = OpenSSL::PKey::EC::Group.new(algorithm_name)
          OpenSSL::PKey::EC.new(pkey_ec_group)
        end

        def self.check_key!(openssl_private_key_bn)
          begin
            pkey_ec_group = OpenSSL::PKey::EC::Group.new(ALGORITHM_NAME)
            pkey_ec_group_curve = OpenSSL::PKey::EC.new(pkey_ec_group)
            pkey_ec_group_curve.private_key = openssl_private_key_bn
            pkey_ec_group_curve.public_key = pkey_ec_group.generator.mul(openssl_private_key_bn)
            pkey_ec_group_curve.check_key
          rescue OpenSSL::PKey::ECError => e 
            raise Sawtooth::Signing::ParseError.new('invalid private key')
          end
        end

      end
    end
  end
end