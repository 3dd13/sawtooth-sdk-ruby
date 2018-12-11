require 'sawtooth/signing/base/context'
require 'sawtooth/signing/base/private_key'
require 'sawtooth/signing/base/public_key'
require 'sawtooth/signing/secp256k1/secp256k1_utils'
require 'sawtooth/signing/secp256k1/secp256k1_context'
require 'sawtooth/signing/secp256k1/secp256k1_private_key'
require 'sawtooth/signing/secp256k1/secp256k1_public_key'
require 'sawtooth/signing/exceptions'
require 'sawtooth/signing/crypto_factory'
require 'sawtooth/signing/signer'


module Sawtooth
  module Signing
    class Core
      ALGORITHM_CONTEXT_MAP = {
        secp256k1: 'Sawtooth::Signing::Secp256k1::Secp256k1Context'
      }.freeze

      # Returns an algorithm instance by name.
      def self.create_context(algorithm_name)
        if context_class = ALGORITHM_CONTEXT_MAP[algorithm_name.to_sym]
          Object.const_get(context_class).new 
        else
          raise Sawtooth::Signing::NoSuchAlgorithmError.new("unknown algorithm #{algorithm_name}")
        end
      end
    end
  end
end