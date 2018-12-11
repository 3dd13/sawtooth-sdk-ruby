require 'sawtooth'

RSpec.describe Sawtooth::Signing::Secp256k1::Secp256k1PublicKey do
  describe "parsing" do
    describe "#from_hex" do
      let(:public_key_hex) { '047a3ac999e93af3010dfbd2554af29cca965340924a2409876dabd76eb43212b74813485fcf5d806dae9ddced97c4be394f994b460e454b557b125e15d44a61fd' }
      let(:public_key) { Sawtooth::Signing::Secp256k1::Secp256k1PublicKey.from_hex(public_key_hex) }

      it "should parse correct hex public key" do
        expect(public_key.algorithm_name).to eq('secp256k1')
        expect(public_key.as_hex).to eq(public_key_hex)
      end

      it "should raise parse error for incorrect hex public key" do
        modified_public_key_hex = public_key_hex.gsub('1', '11')
        expect { Sawtooth::Signing::Secp256k1::Secp256k1PublicKey.from_hex(modified_public_key_hex) }.to raise_error(Sawtooth::Signing::ParseError, 'invalid public key')
      end
    end
  end
end