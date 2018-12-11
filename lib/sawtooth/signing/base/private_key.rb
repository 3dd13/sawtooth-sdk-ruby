module Sawtooth
  module Signing
    module Base
      # A private key instance.
      #  
      # The underlying content is dependent on implementation.
      class PrivateKey

        def initialize(secp256k1_pk)
          raise NotImplementedError
        end

        # Returns the algorithm name used for this private key.
        def algorithm_name
          raise NotImplementedError
        end

        # Return the private key encoded as a hex string.
        def as_hex
          raise NotImplementedError
        end

        # Return the private key bytes.
        def as_bytes
          raise NotImplementedError
        end

        # Create Private Key instance From Hex
        def self.from_hex(private_key_hex)
          raise NotImplementedError
        end

      end
    end
  end
end