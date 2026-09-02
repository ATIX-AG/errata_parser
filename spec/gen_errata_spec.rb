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

  describe '#parse_cves' do
    let(:erratum) { Erratum.new }

    it 'accepts strings' do
      allow(erratum).to receive(:add_cve)
      parser.parse_cves(erratum, 'CVE-1111-11111')
      expect(erratum).to have_received(:add_cve).with('CVE-1111-11111')
    end

    it 'accepts array' do
      allow(erratum).to receive(:add_cve)
      parser.parse_cves(erratum, ['CVE-1111-11111', 'CVE-2222-22222'])
      expect(erratum).to have_received(:add_cve).twice
    end

    it 'ignores other types' do
      erratum.title = 'test'
      allow(parser).to receive(:warn)
      allow(erratum).to receive(:add_cve)
      parser.parse_cves(erratum, nil)
      expect(erratum).not_to have_received(:add_cve)
    end

    it 'does not raise Invalid CVE' do
      expect { parser.parse_cves(erratum, ['ABC-1']) }.not_to raise_error
    end

    it 'raises unknown error' do
      allow(erratum).to receive(:add_cve).and_raise(RuntimeError)
      expect { parser.parse_cves(erratum, ['CVE-1111-111']) }.to raise_error(RuntimeError)
    end
  end

  describe '#gen_ubuntu_errata' do
    let(:usn) { { 'releases' => { 'wolpertinger' => { 'archs' => {} } } } }
    let(:usn_db) { { '1234-1' => usn } }

    it 'does not parse cves, if not specified' do
      allow(parser).to receive(:parse_cves)
      parser.gen_ubuntu_errata(usn_db, {}, {})
      expect(parser).not_to have_received(:parse_cves)
    end

    it 'parses cves' do
      usn['cves'] = ['CVE-3333-33']

      allow(parser).to receive(:parse_cves)
      parser.gen_ubuntu_errata(usn_db, {}, {})
      expect(parser).to have_received(:parse_cves)
    end
  end
end
