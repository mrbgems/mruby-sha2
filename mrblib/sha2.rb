module Digest
  class Base
    def self.digest(str)
      new(str).digest
    end

    def self.hexdigest(str)
      new(str).hexdigest
    end

    def ==(md)
      self.to_s == md.to_s
    end

    def digest!
      str = digest
      reset
      str
    end

    def hexdigest!
      str = hexdigest
      reset
      str
    end

    def digest_length

    end

    alias :length :digest_length
    alias :size :digest_length
  end

  class SHA256 < Base
  end

  class SHA384 < Base
  end

  class SHA512 < Base
  end
end
