##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# SMB Share Brute-Forcer (wordlist)
#
# Tries to connect to each share name from a wordlist against the target,
# using either authenticated credentials or a null / anonymous session.
# Optionally scoped to an Active Directory domain via SMBDomain.
#
# Installation
# ────────────
#   cp smb_share_brute.rb \
#      ~/.msf4/modules/auxiliary/scanner/smb/smb_share_brute.rb
#   msfconsole -q -x "reload_all"
#   use auxiliary/scanner/smb/smb_share_brute
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  # Scanner / report mixins should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  include Msf::OptionalSession::SMB

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'SMB Share Brute-Forcer (wordlist)',
        'Description' => %q{
          Iterates over a user-supplied wordlist and attempts to connect to
          each share name on the target host via SMB tree_connect.
          Supports null / anonymous sessions as well as authenticated access
          with an optional Active Directory domain (SMBDomain).
          Accessible shares are printed and optionally stored in the loot database.
        },
        'Author'      => ['red-team-toolkit'],
        'License'     => MSF_LICENSE,
      )
    )

    register_options(
      [
        OptPath.new('WORDLIST',
          [true, 'Path to file containing share names (one per line)',
           '/usr/share/wordlists/smbshares.txt']),
        OptBool.new('STORE_LOOT',
          [false, 'Save accessible share list to Metasploit loot', true]),
      ]
    )

    deregister_options('RPORT')
  end

  SMB1_PORT   = 139
  SMB2_3_PORT = 445

  # Mirrors smb_enumshares.rb: rport accessor via @rport set per connection attempt
  def rport
    @rport || datastore['RPORT']
  end

  # ── Load and sanitise the wordlist ─────────────────────────────────────────
  def load_wordlist
    path = datastore['WORDLIST']
    unless ::File.exist?(path)
      fail_with(Failure::BadConfig, "Wordlist not found: #{path}")
    end

    ::File.readlines(path, encoding: 'utf-8')
          .map(&:strip)
          .reject { |l| l.empty? || l.start_with?('#') }
  end

  # ── Try to tree_connect to one share name; returns true if accessible ──────
  def try_share(ip, share_name)
    tree = simple.client.tree_connect("\\\\#{ip}\\#{share_name}")
    tree.disconnect! rescue nil
    true
  rescue RubySMB::Error::UnexpectedStatusCode => e
    vprint_status("\\\\#{ip}\\#{share_name} – #{e.status_code.name}")
    false
  rescue RubySMB::Error::InvalidPacket => e
    vprint_error("\\\\#{ip}\\#{share_name} – Invalid packet: #{e}")
    false
  rescue StandardError => e
    vprint_error("\\\\#{ip}\\#{share_name} – #{e.class}: #{e.message}")
    false
  end

  # ── Brute the wordlist against the already-connected session ───────────────
  def brute_shares(ip)
    shares     = load_wordlist
    accessible = []

    print_status("#{ip} – Trying #{shares.size} share name(s) from wordlist…")

    shares.each do |share_name|
      if try_share(ip, share_name)
        print_good("#{ip} – ACCESSIBLE  \\\\#{ip}\\#{share_name}")
        accessible << share_name

        report_note(
          host:   ip,
          proto:  'tcp',
          port:   rport,
          type:   'smb.accessible_share',
          data:   { share: share_name },
          update: :unique_data
        )
      else
        vprint_status("#{ip} – DENIED       \\\\#{ip}\\#{share_name}")
      end
    end

    print_status("#{ip} – Done.  Accessible: #{accessible.size} / #{shares.size}")

    if datastore['STORE_LOOT'] && !accessible.empty?
      loot_data = accessible.map { |s| "\\\\#{ip}\\#{s}" }.join("\n")
      loot_path = store_loot(
        'smb.shares', 'text/plain', ip,
        loot_data, 'smb_brute_shares.txt', 'Accessible SMB Shares'
      )
      print_good("#{ip} – Results saved to loot: #{loot_path}")
    end

    accessible
  end

  # ── Scanner entry point (called once per host in RHOSTS) ──────────────────
  def run_host(ip)
    if session
      print_status("Using existing session #{session.sid}")
      client = session.client
      self.simple = ::Rex::Proto::SMB::SimpleClient.new(
        client.dispatcher.tcp_socket, client: client
      )
      brute_shares(session.address)
    else
      [{ port: SMB1_PORT }, { port: SMB2_3_PORT }].each do |info|
        vprint_status('Connecting to the server...')
        # Assign @rport so it is accessible via the rport method in this module
        # as well as making it accessible to the module mixins
        @rport = info[:port]
        if rport == SMB1_PORT
          connect(versions: [1], backend: :ruby_smb)
        else
          connect(versions: [1, 2, 3])
        end
        smb_login
        results = brute_shares(ip)
        break unless results.empty?
      rescue ::Interrupt
        raise $ERROR_INFO
      rescue Errno::ECONNRESET => e
        vprint_error(e.message)
      rescue Errno::ENOPROTOOPT
        print_status('Wait 5 seconds before retrying...')
        select(nil, nil, nil, 5)
        retry
      rescue Rex::ConnectionTimeout => e
        print_error(e.to_s)
      rescue Rex::Proto::SMB::Exceptions::LoginError => e
        print_error(e.to_s)
      rescue RubySMB::Error::RubySMBError => e
        print_error("RubySMB encountered an error: #{e}")
      rescue RuntimeError => e
        print_error e.to_s
      rescue StandardError => e
        vprint_error("Error: '#{ip}' '#{e.class}' '#{e}'")
      ensure
        disconnect
      end
    end
  end
end
