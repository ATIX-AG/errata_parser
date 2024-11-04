# frozen_string_literal: true

require 'spec_helper'
require 'rspec/collection_matchers'
require './lib/deb_erratum_rss'

RSpec.describe Feedjira::Parser::RSSEntry do
  subject(:entry) { described_class.new }

  it { is_expected.to respond_to :erratum_id }

  [
    ['default', "DSA-0815-1\nsomething", 'DSA-0815-1'],
    ['whitespaces', " DSA-4711-1 \nfoo", 'DSA-4711-1'],
    ['USN', "USN-0815-1:\nsomething", 'USN-0815-1'],
    ['USN-whitespaces', " USN-4711-1: \nfoo", 'USN-4711-1']
  ].each do |testname, input, output|
    describe "with #{testname}" do
      subject { entry.erratum_id }

      # rubocop:disable RSpec/SubjectStub
      before { allow(entry).to receive(:title).and_return(input) }
      # rubocop:enable RSpec/SubjectStub

      it { is_expected.to eq(output) }
    end
  end
end

RSpec.describe LatestDlaErratum do
  subject { described_class.new }

  it { is_expected.to be_a LatestErratum }
end

RSpec.describe LatestDsaErratum do
  subject { described_class.new }

  it { is_expected.to be_a LatestErratum }
end

RSpec.describe LatestUsnErratum do
  subject { described_class.new }

  it { is_expected.to be_a LatestErratum }
end

RSpec.describe LatestErratum do
  subject(:latest_errata) { described_class.new('url') }

  let(:http_response) { instance_double(Net::HTTPResponse) }

  before do
    allow(http_response).to receive(:[]).with('content-type').and_return('application/rss+xml')
    allow(http_response).to receive(:body).and_return(File.read('spec/fixtures/dsa.xml'))
    allow(Net::HTTP).to receive(:get_response).and_return(http_response)
  end

  describe '#entries' do
    subject { latest_errata.entries }

    it { is_expected.not_to be_empty }
    it { is_expected.to be_a(Array) }
  end

  describe '#recent' do
    subject { latest_errata.recent(num) }

    let(:num) { 2 }

    it { is_expected.not_to be_empty }
    it { is_expected.to have(num).entries }
  end

  it "accepts content-type 'text/xml'" do
    allow(http_response).to receive(:[]).with('content-type').and_return('text/xml')

    expect(described_class.new('url')).to be_a described_class
  end

  it 'fails unknown content-type' do
    allow(http_response).to receive(:[]).with('content-type').and_return('text/html')

    expect { described_class.new('url') }.to raise_error(RuntimeError)
  end
end
