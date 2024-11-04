# frozen_string_literal: true

require 'spec_helper'
require './lib/ubuntu_security_api'

RSpec.describe UbuntuSecurityApi do
  let(:usa) { described_class.new(retry: 3) }

  context 'when get' do
    let(:conn) { instance_double(Faraday::Connection) }
    let(:notice) { { 'id' => 'USN-1337-1', 'published' => '2024-10-23T19:45:29.964Z' } }
    let(:notices) do
      [
        notice,
        { 'id' => 'USN-1237-1', 'published' => '2024-10-22T18:45:29.964Z' },
        { 'id' => 'USN-1236-1', 'published' => '2024-10-22T17:45:29.964Z' },
        { 'id' => 'USN-1235-1', 'published' => '2024-10-22T16:45:29.964Z' },
        { 'id' => 'USN-1234-1', 'published' => '2024-10-22T15:45:29.964Z' }
      ]
    end
    let(:response) { instance_double(Faraday::Response) }

    before do
      allow(usa).to receive(:conn).and_return(conn)
      allow(conn).to receive(:get).and_return(response)
      allow(response).to receive(:body).and_return({ 'notices' => notices })
    end

    it 'latest errata' do
      expect(usa.latest_errata).to eq(notices)
    end

    it 'latest n errata' do
      allow(response).to receive(:body).and_return({ 'notices' => notices.append({ 'id' => 'too_old' }) })
      expect(usa.latest_errata(nil, 5)).to eq(notices)
    end

    it 'latest release erratua' do
      usa.latest_errata('bionic')
      expect(conn).to have_received(:get).with('/security/notices.json',
                                               { release: 'bionic',
                                                 order: 'newest',
                                                 show_hidden: false })
    end

    it 'latest erratum' do
      allow(response).to receive(:body).and_return({ 'notices' => notices })

      expect(usa.latest_erratum).to eq(notice)
    end

    it "yesterday's erratum" do
      notice_today = { 'id' => 'USN-4711-1', 'published' => '2024-10-24T19:45:29.964Z' }
      allow(response).to receive(:body).and_return({ 'notices' => [notice_today, *notices.slice(0, 4)] })
      allow(Date).to receive(:today).and_return(Date.new(2024, 10, 24))

      expect(usa.yesterdays_erratum).to eq(notice)
    end

    it "no yesterday's erratum" do
      allow(Date).to receive(:today).and_return(Date.new(2024, 10, 22))
      allow(response).to receive(:body).and_return({ 'notices' => notices })

      expect { usa.yesterdays_erratum }.to raise_error(RuntimeError)
    end

    # rubocop:disable RSpec/ExampleLength
    it 'retries on server-error 5XX' do
      raise_server_error = 2

      allow(conn).to receive(:get).thrice do
        if raise_server_error.zero?
          response
        else
          raise_server_error -= 1
          raise Faraday::ServerError
        end
      end

      expect(usa.latest_errata).to eq(notices)
    end
    # rubocop:enable RSpec/ExampleLength

    it 'fails on client-error 4XX' do
      allow(response).to receive(:body).and_return({ 'notices' => [] })
      allow(conn).to receive(:get).and_raise(Faraday::ClientError).once

      expect { usa.latest_errata }.to raise_error(Faraday::ClientError)
    end
  end
end
