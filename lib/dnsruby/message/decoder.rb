module Dnsruby
class MessageDecoder #:nodoc: all
  attr_reader :index
  def initialize(data)
    @data = data
    @index = 0
    @limit = data.length
    yield self if block_given?
  end

  def has_remaining
    @limit - @index > 0
  end

  def get_length16
    len, = self.get_unpack('n')
    save_limit = @limit
    @limit = @index + len
    d = yield(len)
    if @index < @limit
      message = "Junk exists; limit = #{@limit}, index = #{@index}"
      raise DecodeError.new(message)
    elsif @limit < @index
      message = "Limit exceeded; limit = #{@limit}, index = #{@index}"
      raise DecodeError.new(message)
    end
    @limit = save_limit
    d
  end

  def get_bytes(len = @limit - @index)
    d = @data[@index, len]
    @index += len
    d
  end

  def get_unpack(template)
    len = 0
    littlec = ?c
    bigc = ?C
    littleh = ?h
    bigh = ?H
    littlen = ?n
    bign = ?N
    star = ?*

    if (littlec.class != Fixnum)
      #  We're using Ruby 1.9 - convert the codes
      littlec = littlec.getbyte(0)
      bigc = bigc.getbyte(0)
      littleh = littleh.getbyte(0)
      bigh = bigh.getbyte(0)
      littlen = littlen.getbyte(0)
      bign = bign.getbyte(0)
      star = star.getbyte(0)
    end

    template.each_byte {|byte|
      case byte
        when littlec, bigc
          len += 1
        when littleh, bigh
          len += 1
        when littlen
          len += 2
        when bign
          len += 4
        when star
          len = @limit - @index
        else
          raise StandardError.new("unsupported template: '#{byte.chr}' in '#{template}'")
      end
    }
    raise DecodeError.new('limit exceeded') if @limit < @index + len
    arr = @data.unpack("@#{@index}#{template}")
    @index += len
    arr
  end

  def get_string
    len = @data[@index]
    if len.class == String
      len = len.getbyte(0)
    end
    raise DecodeError.new("limit exceeded\nlimit = #{@limit}, index = #{@index}, len = #{len}\n") if @limit < @index + 1 + (len ? len : 0)
    d = @data[@index + 1, len]
    @index += 1 + len
    d
  end

  def get_string_list
    strings = []
    while @index < @limit
      strings << self.get_string
    end
    strings
  end

  def get_name
    Name.new(self.get_labels)
  end

  def get_labels(limit=nil)
    limit = @index if !limit || @index < limit
    d = []
    while true
      temp = @data[@index]
      if temp.class == String
        temp = temp.getbyte(0)
      end
      case temp # @data[@index]
        when 0
          @index += 1
          return d
        when 192..255
          idx = self.get_unpack('n')[0] & 0x3fff
          if limit <= idx
            raise DecodeError.new('non-backward name pointer')
          end
          save_index = @index
          @index = idx
          d += self.get_labels(limit)
          @index = save_index
          return d
        else
          d << self.get_label
      end
    end
    d
  end

  def get_label
    begin
      #         label = Name::Label.new(Name::decode(self.get_string))
      label = Name::Label.new(self.get_string)
      return label
        #          return Name::Label::Str.new(self.get_string)
    rescue ResolvError => e
      raise DecodeError.new(e) # Turn it into something more suitable
    end
  end

  def get_question
    name = self.get_name
    type, klass = self.get_unpack('nn')
    q = Question.new(name, type, klass)
    q
  end

  def get_rr
    name = self.get_name
    type, klass, ttl = self.get_unpack('nnN')
    klass = Classes.new(klass)
    typeclass = RR.get_class(type, klass)
    #  @TODO@ Trap decode errors here, and somehow mark the record as bad.
    #  Need some way to represent raw data only
    rec = self.get_length16 { typeclass.decode_rdata(self) }
    rec.name = name
    rec.ttl = ttl
    rec.type = type
    rec.klass = klass
    rec
  end
end

end