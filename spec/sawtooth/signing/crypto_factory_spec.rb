require 'sawtooth'

RSpec.describe Sawtooth::Signing::CryptoFactory do
  let(:private_key) { '2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088' }

  describe "#new_signer" do
    it "should return signer instance" do
      secp256k1_context = Sawtooth::Signing::Core.create_context('secp256k1')
      crypto_factory = Sawtooth::Signing::CryptoFactory.new(secp256k1_context)
      
      expect(crypto_factory.new_signer(private_key)).to be_instance_of(Sawtooth::Signing::Signer)
    end
  end
end