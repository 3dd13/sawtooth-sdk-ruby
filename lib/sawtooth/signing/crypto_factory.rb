module Sawtooth
  module Signing

    # Factory for generating Signers.
    class CryptoFactory

      attr_accessor :context

      def initialize(context)
        @context = context
      end

      # Create a new signer for the given private key.
      def new_signer(private_key)
        Signer.new(@context, private_key)
      end

    end
  end
end
