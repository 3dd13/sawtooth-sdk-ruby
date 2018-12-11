require 'sawtooth'

RSpec.describe Sawtooth::Signing::Secp256k1::Secp256k1PrivateKey do
  describe "parsing" do
    describe "#from_hex" do
      let(:private_key_hex) { '86bcc5485166e49e2e7815de6d8f408beaaa6983d98df04fed033618f375e8af' }
      let(:private_key) { Sawtooth::Signing::Secp256k1::Secp256k1PrivateKey.from_hex(private_key_hex) }

      it "should parse correct hex private key" do
        expect(private_key.algorithm_name).to eq('secp256k1')
        expect(private_key.as_hex).to eq(private_key_hex)
      end

      it "should raise parse error for incorrect hex private key" do
        modified_private_key_hex = private_key_hex.gsub('1', '11')
        expect { Sawtooth::Signing::Secp256k1::Secp256k1PrivateKey.from_hex(modified_private_key_hex) }.to raise_error(Sawtooth::Signing::ParseError, 'invalid private key')
      end
    end
  end
end