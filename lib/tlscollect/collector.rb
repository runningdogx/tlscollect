require 'pp'
module TLSCollect
  class CollectException < Exception
  end
  
  class Collector
    
    attr_accessor :host, :addr, :port, :ctimeout,
                  :default_cipher, :protocols, :ciphers,
                  :certificate, :verified, :timestamp, :totals
  
    @@default_ca_cert_paths = [
      "/etc/ssl/certs/ca-certificates.crt",
      "certs/ca-bundle.crt",
    ]

    @@protocols = [:"TLSv1.2", :"TLSv1.1", :"TLSv1", :"SSLv3", :"SSLv2"]
    @@basic_ciphers = 'ALL:aNULL:eNULL'
  
    def initialize(params)
      @ca_cert_path = (params[:ca_cert_path] ? params[:ca_cert_path] : find_ca_certs)
      puts "CA CERT PATH IS #{@ca_cert_path}"
      
      @host = params[:host]
      @addr = (params[:addr] ? params[:addr] : addr = TCPSocket.gethostbyname(host)[3])
      @port = params[:port]
      @ctimeout = params[:ctimeout]
      @default_cipher = nil
      @verified = false
      @protocols = []
      @ciphers = []
      @candidate_ciphers = []
      #@totals = {'null' => 0, 'export' => 0, 'low' => 0,
      #           'medium' => 0, 'high' => 0, 'dhe' => 0}
    end

    def find_ca_certs
      @@default_ca_cert_paths.each do |path|
        if File.exists?(path)
          return path
        end
      end
    end

    def to_h
      begin
        i = 0
        h = { 'summ' => { 'collected_at' => timestamp,
                          'tls1_2'   => tls1_2?,
                          'tls1_1'   => tls1_1?,
                          'tls1_0'   => tls1_0?,
                          'ssl3_0'   => ssl3_0?,
                          'ssl2_0'   => ssl2_0?
                        },
              'certificate' => certificate.to_h,
              'ciphers' => ciphers.collect {|c| 
                c.order = i
                i += 1
                c.to_h
              }
        }
      rescue StandardError => e
        puts "ERROR: #{e}"
      end
      h
    end
  
    def tls1_2?
      protocols.include?(:"TLSv1.2") #|| tls1_1?
    end

    def tls1_1?
      protocols.include?(:"TLSv1.1") #|| tls1_0?
    end

    def tls1_0?
      protocols.include?(:"TLSv1")
    end

    def ssl3_0?
      protocols.include?(:"SSLv3")
    end

    def ssl2_0?
      protocols.include?(:"SSLv2")
    end

    def pci_ready?
      Cipher.pci_ready?(ciphers) &&
      !(protocols.include?(:"SSLv2") && protocols.length == 1)
    end

    def collect_basic
      @timestamp = Time.now
      @protocols = remote_protocols
      unless init_ciphers
        raise CollectException.new, "Failed to initialize collection context."
      end
      @verified = certificate_verified?
      @default_cipher, @certificate = gather_defaults(@protocols.first, 'ALL:aNULL:eNULL')
      unless @default_cipher && @certificate
        raise CollectException.new, "Could not determine default cipher and certificate."
      end
    end

    def collect_cipher_order
      @ciphers = remote_ciphers
      #test_cipher_order
    end
  
    def init_ciphers
      sock = get_sock
      return nil unless sock
      context = OpenSSL::SSL::SSLContext.new()
      context.ciphers = "ALL:aNULL:eNULL"
      ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
      @candidate_ciphers = ssl.context.ciphers.collect { |c| Cipher.parse(c) }
    end

    def get_sock
      begin
        timeout(@ctimeout) do
          #puts "getting socket for #{addr} on port #{port}"
          TCPSocket.open(addr, port)
        end
      rescue Timeout::Error
        nil
      end
    end
  
    # The grand purpose of this is to set up a typical ssl connection,
    # and connect.  If a block is passed, at various stages control
    # is passed to the block with a (state, obj) pair.
    # - after sslcontext creation (:context, SSLContext)
    # - after sslsocket creation (:sslsocket, SSLSocket)
    def sslconnect(sock = nil, protocol = nil)
      if not sock
        return nil unless sock = get_sock
      end

      if protocol
        protocol = protocol.to_s
        protocol[5] = '_' if protocol[5] == '.'
        context = OpenSSL::SSL::SSLContext.new(protocol)
      else
        context = OpenSSL::SSL::SSLContext.new()
      end
      # this only applies server-side
      #context.tmp_dh_callback = proc {|s, f, kl| puts "DH Keylength: #{kl}"}
      yield :context, context if block_given?
      ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
      ssl.hostname = @host
      yield :sslsocket, ssl if block_given?

      # return the connected ssl socket, or nil on failure
      begin
        timeout(@ctimeout) do
          ssl.connect
        end
      rescue
        nil
      end
    end
  
    def certificate_verified?
      verified = false
      begin
        ssl = sslconnect do |state, object|
          if state == :sslcontext
            object.ciphers = @@basic_ciphers
            object.ca_file = @ca_cert_path
            object.verify_depth = 16
            object.verify_mode = OpenSSL::SSL::VERIFY_PEER
          end
        end
        verified = true if ssl
      rescue
        puts "Certificate for #{@host} is unverified"
      end
    
      verified
    end
  
    def remote_protocols
      @@protocols.reject do |p|
        if p == :SSLv2
          cipher,cert = gather_defaults(:"SSLv2")
          not cipher
        else
          not sslconnect(nil, p)
        end
      end
    end

    def dh_process(session, xflag, keylength)
      puts "DH CALLBACK: #{keylength}"
    end
  
    def gather_defaults(protocol = nil, cipherlist = nil)
      cipher = cert = nil
      ssl = sslconnect(nil, protocol) { |state,obj|
          obj.ciphers = cipherlist if cipherlist and state==:SSLContext
          
      }
      if ssl
        cipher = Cipher.parse(ssl.cipher)
        cert = Certificate.parse(:raw => ssl.peer_cert, :verified => verified)
      end

      #puts "Failure while gathering defaults" unless (cipher && cert)
      return [ cipher, cert ]
    end
  
    def remote_ciphers(testprot = @protocols.first)
      @candidate_ciphers.reject! { |cipher|
        #puts "testing cipher #{cipher.name} for compat with #{testprot}"
        not cipher.valid_for_protocol?(testprot)
      }

      @candidate_ciphers.reject do |cipher|
        #puts cipher.name
        ssl = sslconnect(ssl, testprot) do |state, obj|
          if state == :context
            begin
              obj.ciphers = [cipher.to_a]
            rescue
              nil
            end
          end
        end

        not ssl
      end
    end

    def test_cipher_order
      t_ciphers = @ciphers.collect {|c| c.to_a}
      @ciphers = []
      (0..(t_ciphers.length - 1)).each do |i|
        sock = get_sock
        if ssl = sslconnect(sock) {|state, object|
          begin
            object.ciphers = t_ciphers if state == :context
          rescue
            nil
          end
        }
          t_ciphers, d_ciphers = delete_cipher(t_ciphers, ssl.cipher)
          d_ciphers.each do |d|
            tc = Cipher.parse(d)
            if j = included_cipher?(tc)
              #puts "Adding protocols #{tc.protocols.join(', ')} to #{@ciphers[j].cipher}"
              @ciphers[j].protocols << tc.protocols if supported_protocol?(tc.protocols)
              @ciphers[j].protocols.flatten!
            else 
              @ciphers << tc if supported_protocol?(tc.protocols)
            end
          end
        end
      end
      @default_cipher = @ciphers.first
      @ciphers
    end
  
    def included_cipher?(cipher)
      @ciphers.each do |c|
        if c.cipher == cipher.cipher
          return @ciphers.index(c)
        end
      end
      nil
    end
  
    def supported_protocol?(protocol)
      protocols.each {|p| return true if @protocols.include?(p)}
      false
    end
  
    def delete_cipher(ciphers, cipher)
      cipher = Cipher.parse(cipher).cipher
      d = []
      ciphers.each { |c|
        d << ciphers.delete(c) if Cipher.parse(c).cipher == cipher
      }
    
      [ciphers, d]
    end
  end
end
