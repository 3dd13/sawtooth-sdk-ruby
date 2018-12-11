require 'digest'
require 'openssl'

require 'sawtooth/signing/base/public_key'
require 'sawtooth/signing/secp256k1/secp256k1_utils'


module Sawtooth
  module Signing
    module Secp256k1
      class Secp256k1PublicKey < Sawtooth::Signing::Base::PublicKey
        include Sawtooth::Signing::Secp256k1::Secp256k1Utils

        ALGORITHM_NAME = 'secp256k1'

        attr_accessor :openssl_public_key_point

        def initialize(openssl_public_key_point)
          @openssl_public_key_point = openssl_public_key_point
        end

        def algorithm_name
          ALGORITHM_NAME
        end

        # public key in hex format
        def as_hex
          openssl_public_key_point.to_bn.to_s(16).downcase
        end

        # Return the private key bytes.
        def as_bytes
          hex_to_binary(as_hex)
        end

        # Create Public Key instance From Hex
        def self.from_hex(hex_str)
          begin
            ec_group = OpenSSL::PKey::EC::Group.new(ALGORITHM_NAME)
            openssl_public_key_bn = OpenSSL::BN.new(hex_str, 16)
            openssl_public_key_point = OpenSSL::PKey::EC::Point.new(ec_group, openssl_public_key_bn)
            self.new(openssl_public_key_point)
          rescue OpenSSL::PKey::EC::Point::Error => e
            raise Sawtooth::Signing::ParseError.new('invalid public key')
          end
        end

        def self.from_bytes(byte_str)
          from_hex(binary_to_hex(byte_str))
        end
      end
    end
  end
end
