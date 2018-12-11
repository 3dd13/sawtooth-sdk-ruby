require 'openssl'


module Sawtooth
  module Signing
    module Secp256k1
      module Secp256k1Utils
        private

        def new_pkey_ec_group_curve
          pkey_ec_group = OpenSSL::PKey::EC::Group.new(algorithm_name)
          OpenSSL::PKey::EC.new(pkey_ec_group)
        end

        def binary_to_hex(binary_str)
          binary_str.unpack('H*').first
        end

        def hex_to_binary(hex_str)
          hex_str.scan(/../).map { |s| s.hex }.pack('c*')
        end
      end
    end
  end
end