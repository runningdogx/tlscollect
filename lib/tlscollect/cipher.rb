module TLSCollect
  class Cipher
    
    attr_accessor :name, :kx_alg, :auth_alg, :bulk_alg, :bulk_mode, :bulk_bits,
                  :hash_alg, :hash_bits, :protocols, :key_length, :order

    @@ciphers = [:None, :AES, :AES, :CAMELLIA, :CAMELLIA,
                 :"3DES", :DES, :IDEA, :RC4, :RC2, :SEED, :ARIA]
    @@mac = [:MD5, :SHA1, :SHA256, :AEAD]
    @@mode = [:CBC, :GCM, :CTR]
    @@kx = [:DH, :ECDH, :"ECDH/ECDSA", :"ECDH/RSA", :RSA, :SRP, :PSK]
    @@au = [:None, :RSA, :DSS, :ECDSA, :ECDH, :PSK]
  
    def self.hash_parse(hash)
      /^(?<hashname>MD5|SHA)(?<hashbits>256|384|512)?$/ =~ hash
      unless hashbits
        case hashname
          when 'MD5'
            hashbits = 128
          when 'SHA'
            hashbits = 160
          else
            puts "XXX unknown bits for hash: #{hash}"
            hashbits = nil
        end
      end
      [hash, hashbits.to_i]
    end

    def self.bulk_parse(bulk)
      n_alg_mode = 'CBC'
      while bulk.size > 1
        case bulk[-1]
          when '128'  # garbage SRP ciphersuites
          when '256'  # garbage SRP ciphersuites
          when 'CBC'  # no shit
          when 'EDE'  # already labelled 3des
          when 'CBC3'
            bulk[0] = '3DES'
          when 'GCM'
            n_alg_mode = 'GCM'
          when 'CTR'
            n_alg_mode = 'CTR'
          else
            puts "XXX unrecognized #{bulk[-1]}"
        end
        bulk.pop
      end
      /^(?<realcipher>.*)(128|256)$/ =~ bulk[0]
      n_alg = realcipher || bulk[0]
      [n_alg, n_alg_mode]
    end

    def self.parse(cipher_a)
      c = cipher_a[0].split('-')

      # handle export tags
      if c[0] == 'EXP'
        c.shift
        exp = true
      else
        exp = false
      end

      # hash is easy
      n_hash_alg, n_hash_bits = hash_parse(c.pop)

      if c[0].match(/^A(EC)?DH$/)
        # if Anon DH or ECDH, set auth mode to null
        n_kx = c[0]
        n_auth = 'NULL'
        c.shift
      elsif c[0].match(/^((EC)?DHE?|EDH)$/)
        # if Authenticated DH or ECDH, normalize and store
        c[0] = 'DHE' if c[0] == 'EDH'
        n_kx = c[0]
        n_auth = c[1]
        c.shift(2)
      elsif c[0] == 'PSK' || c[0] == 'SRP'
        # if PSK or SRP, handle separately
        n_kx = n_auth = c[0]
        c.shift
        if c[0] == 'RSA' || c[0] == 'DSS'
          n_auth = c[0]
          c.shift
        end
      else
        # If no Auth method is listed, it's RSA
        n_kx = n_auth = "RSA"
      end

      n_bulk = c.join('-')
      n_cipher = cipher_a[0]
      n_protocols = [cipher_a[-3].split('/')].flatten.map{|p| p.to_sym}
      n_protocols = [:"TLSv1.2"] if n_hash_bits >= 256
      n_key_length = cipher_a[-2]

      n_bulk_alg, n_bulk_mode = self.bulk_parse(c)
      n_bulk_bits = cipher_a.last
    
      self.new(:cipher => n_cipher,
               :kx_alg => n_kx,
               :auth_alg => n_auth,
               :bulk_alg => n_bulk_alg,
               :bulk_mode => n_bulk_mode,
               :bulk_bits => n_bulk_bits,
               :hash_alg => n_hash_alg,
               :hash_bits => n_hash_bits,
               :protocols => n_protocols,
               :key_length => n_key_length,
               :export => exp)
    end
  
    def initialize(params)
      @name = params[:cipher]
      @kx_alg = params[:kx_alg]
      @auth_alg = params[:auth_alg]
      @bulk_alg = params[:bulk_alg]
      @bulk_mode = params[:bulk_mode]
      @bulk_bits = params[:bulk_bits]
      @hash_alg = params[:hash_alg]
      @hash_bits = params[:hash_bits]
      @protocols = params[:protocols]
      @key_length = params[:key_length]
      @export = params[:export]
      @order = 0
    end
  
    def cipher
      name
    end

    def to_s
      cipher + " " + protocols.join('/')
    end

    def detailed_s
      "%s %s (%s:%i) (%s:%i) [%s]" %
        [kx_alg, auth_alg, bulk_alg, key_length, hash_alg, hash_bits,
        protocols.join('/')]
    end
  
    def to_a
      [cipher, protocols.join('/'), key_length, bulk_bits]
    end
  
    def to_h
      {
       'name'     => cipher,
       'kx_alg'   => kx_alg,
       'auth_alg' => auth_alg,
       'bulk_alg' => bulk_alg,
       'bulk_mode' => bulk_mode,
       'bulk_bits' => bulk_bits,
       'hash_alg' => hash_alg,
       'hash_bits' => hash_bits,
       'tls1_2'   => tls1_2?,
       'tls1_1'   => tls1_1?,
       'tls1_0'   => tls1_0?,
       'ssl3_0'   => ssl3_0?,
       'ssl2_0'   => ssl2_0?,
       'key_length' => key_length,
       'preference' => order
       }      
    end
  
    def tls1_2?
      protocols.include?(:"TLSv1.2") || tls1_1?
    end
  
    def tls1_1?
      protocols.include?(:"TLSv1.1") || tls1_0?
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

    def weak?
      @key_length < 80
    end

    def noauth?
      @name[0..3] == 'ADH-' or @name[0..5] == 'AECDH-'
    end

    # Test compatibility with a specified protocol
    def valid_for_protocol?(p)
      tproto = @protocols
      if protocols.include?(:"TLSv1")
        tproto += [:"TLSv1.1", :"TLSv1.2"]
      end
      tproto.include?(p)
    end
  end
end
