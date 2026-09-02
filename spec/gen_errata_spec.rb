# frozen_string_literal: true

require 'spec_helper'
require 'rspec/collection_matchers'
require './gen_errata'

RSpec.describe Erratum do
  subject(:erratum) { described_class.new }

  it { is_expected.to respond_to :title }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :cves }
  it { is_expected.to respond_to :source_package }
  it { is_expected.to respond_to :fixed_version }
  it { is_expected.to respond_to :dbts_bugs }
  it { is_expected.to respond_to :description= }

  describe '#add_cve' do
    it 'adds valid CVE' do
      erratum.add_cve 'CVE-0815-123'
      expect(erratum.cves).to eq(['CVE-0815-123'])
    end

    it 'raises on invalid CVE' do
      expect { erratum.add_cve 'CVE-08' }.to raise_error(RuntimeError)
    end

    it 'adds CVEs to list' do
      erratum.add_cve 'CVE-0815-123'
      erratum.add_cve 'CVE-0815-567'
      expect(erratum.cves).to eq(['CVE-0815-123', 'CVE-0815-567'])
    end
  end
end

RSpec.describe DebianErrataParser do
  subject(:parser) { described_class.new }

  it { is_expected.to respond_to :info_state }
  it { is_expected.to respond_to :info_state_cmplt }
end
