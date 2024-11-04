# frozen_string_literal: true

require 'spec_helper'
require './lib/errata_statistics'

RSpec.describe ErrataStatistics do
  subject { described_class.new('dummy.json') }

  describe '#moving_average' do
    subject { described_class.new('dummy.json').moving_average(*args) }

    [
      ['simple', [5, 15, 2], 10],
      ['float', [5, 10, 4], 6.25],
      ['float', [6.25, 5, 5], 6.0]
    ].each do |testname, input, output|
      describe "with #{testname}" do
        let(:args) { input }

        it { is_expected.to eq output }
        it { is_expected.to be_a Float }
      end
    end
  end
end
