#--
#Copyright 2007 Nominet UK
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License. 
#You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0 
#
#Unless required by applicable law or agreed to in writing, software 
#distributed under the License is distributed on an "AS IS" BASIS, 
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#See the License for the specific language governing permissions and 
#limitations under the License.
#++
require 'rubygems'
require 'test/unit'
require 'dnsruby'
include Dnsruby
class TestRR < Test::Unit::TestCase
  def test_rr
    #------------------------------------------------------------------------------
    # Canned data.
    #------------------------------------------------------------------------------
    
    name			= "foo.example.com";
    klass			= "IN";
    ttl				= 43200;
    
    rrs = [
    {  	#[0]
      :type        => Types.A,
      :address     => '10.0.0.1',  
    }, 
    {	#[1]
      :type      => Types::AAAA,
      :address     => '102:304:506:708:90a:b0c:d0e:ff10',
    }, 
    {	#[2]
      :type         => 'AFSDB',
      :subtype      => 1,
      :hostname     => 'afsdb-hostname.example.com',
    }, 
    {	#[3]
      :type         => Types.CNAME,
      :domainname        => 'cname-cname.example.com',
    }, 
    {   #[4]
      :type         => Types.DNAME,
      :domainname        => 'dname.example.com',
    },
    {	#[5]
      :type         => Types.HINFO,
      :cpu          => 'test-cpu',
      :os           => 'test-os',
    }, 
    {	#[6]
      :type         => Types.ISDN,
      :address      => '987654321',
      :subaddress           => '001',
    }, 
    {	#[7]
      :type         => Types.MB,
      :domainname      => 'mb-madname.example.com',
    }, 
    {	#[8]
      :type         => Types.MG,
      :domainname   => 'mg-mgmname.example.com',
    }, 
    {	#[9]
      :type         => Types.MINFO,
      :rmailbx      => 'minfo-rmailbx.example.com',
      :emailbx      => 'minfo-emailbx.example.com',
    }, 
    {	#[10]
      :type         => Types.MR,
      :domainname      => 'mr-newname.example.com',
    }, 
    {	#[11]
      :type         => Types.MX,
      :preference   => 10,
      :exchange     => 'mx-exchange.example.com',
    },
    {	#[12]
      :type        => Types.NAPTR,
      :order        => 100,
      :preference   => 10,
      :flags        => 'naptr-flags',
      :service      => 'naptr-service',
      :regexp       => 'naptr-regexp',
      :replacement  => 'naptr-replacement.example.com',
    },
    {	#[13]
      :type         => Types.NS,
      :domainname      => 'ns-nsdname.example.com',
    },
    {	#[14]
      :type         => Types.NSAP,
      :afi          => '47',
      :idi          => '0005',
      :dfi          => '80',
      :aa           => '005a00',
      :rd           => '1000',
      :area         => '0020',
      :id           => '00800a123456',
      :sel          => '00',
      #      #:address => '4700580005a001000002000800a12345600'
      #      :address => '47000580005a0000001000002000800a12345600'
    },
    {	#[15]
      :type         => Types.PTR,
      :domainname     => 'ptr-ptrdname.example.com',
    },
    {	#[16] 
      :type         => Types.PX,
      :preference   => 10,
      :map822       => 'px-map822.example.com',
      :mapx400      => 'px-mapx400.example.com',
    },
    {	#[17]
      :type         => Types.RP,
      :mailbox		 => 'rp-mbox.example.com',
      :txtdomain     => 'rp-txtdname.example.com',
    },
    {	#[18]
      :type         => Types.RT,
      :preference   => 10,
      :intermediate => 'rt-intermediate.example.com',
    },
    {	#[19]
      :type         => Types.SOA,
      :mname        => 'soa-mname.example.com',
      :rname        => 'soa-rname.example.com',
      :serial       => 12345,
      :refresh      => 7200,
      :retry        => 3600,
      :expire       => 2592000,
      :minimum      => 86400,
    },
    {	#[20]
      :type         => Types.SRV,
      :priority     => 1,
      :weight       => 2,
      :port         => 3,
      :target       => 'srv-target.example.com',
    },
    {	#[21]
      :type         => Types.TXT,
      :strings => 'txt-txtdata',
    },
    {	#[22]
      :type         => Types.X25,
      :address      => '123456789',
    },
    {	#[23]
      :type        => Types.LOC,
      :version      => 0,
      :size         => 3000,
      :horiz_pre    => 500000,
      :vert_pre     => 500,
      :latitude     => 2001683648,
      :longitude    => 1856783648,
      :altitude     => 9997600,
    }, 	#[24]
    {
      :type         => Types.CERT,
      :certtype   => 3,
      :keytag			 => 1,
      :alg    => 1,
      :cert  => '123456789abcdefghijklmnopqrstuvwxyz',
    },
    {	#[25]
      :type         => Types.SPF,
      :strings      => 'txt-txtdata',
    },
    ]
    
    
    #------------------------------------------------------------------------------
    # Create the packet
    #------------------------------------------------------------------------------
    
    message = Message.new
    assert(message,         'Message created');
    
    
    rrs.each do |data|
      data.update({	   :name => name,
        :ttl  => ttl,
      })
      rr=RR.create(data)
      
      message.add_answer(rr);
    end
    
    #------------------------------------------------------------------------------
    # Re-create the packet from data.
    #------------------------------------------------------------------------------
    data = message.encode;
    assert(data,            'Packet has data after pushes');
    
    message=nil;
    message= Message.decode(data);
    
    assert(message,          'Packet reconstructed from data');
    
    answer = message.answer;
    
    i = 0
    rrs.each do |rec|
      ret_rr = answer[i]
      i += 1
      rec.each do |key, value|
        #        method = key+'=?'
        x = ret_rr.send(key)
        if (ret_rr.kind_of?RR::CERT and (key == :alg or key == :certtype))
          assert_equal(value.to_s, x.code.to_s.downcase, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
        elsif (ret_rr.kind_of?RR::TXT and (key == :strings)) 
          assert_equal(value.to_s.downcase, x[0].to_s.downcase, "TXT strings wrong")
        else
          if (key == :type)
            assert_equal(Types.new(value).to_s.downcase, x.to_s.downcase, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
          else
            assert_equal(value.to_s.downcase, x.to_s.downcase, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
          end
        end
      end
    end
    
    
    
    while (!answer.empty? and !rrs.empty?)
      data = rrs.shift;
      rr   = answer.shift;
      type = data[:type];
      
      assert(rr,                         "#{type} - RR defined");    
      assert_equal(name,       	rr.name.to_s,    "#{type} - name() correct");         
      assert_equal(klass,      	Classes.to_string(rr.class::ClassValue),   "#{type} - class() correct");  
      assert_equal(ttl,        	rr.ttl,     "#{type} - ttl() correct");                
      
      #	foreach my $meth (keys %{data}) {
      data.keys.each do |meth|
        ret = rr.send(meth)
        if (rr.kind_of?RR::CERT and (meth == :alg or meth == :certtype))
          assert_equal(data[meth].to_s, ret.code.to_s.downcase, "#{type} - #{meth}() correct")
        elsif (rr.kind_of?RR::TXT and (meth == :strings)) 
          assert_equal(data[meth].to_s, ret[0].to_s.downcase, "TXT strings wrong")
        else
          if (meth == :type)
            assert_equal(Types.new(data[meth]).to_s.downcase, ret.to_s.downcase, "#{type} - #{meth}() correct");
          else
            assert_equal(data[meth].to_s, ret.to_s.downcase, "#{type} - #{meth}() correct");
          end
        end
      end
      
      rr2 = RR.new_from_string(rr.to_s)
      assert_equal(rr.to_s,   rr2.to_s, "#{type} - Parsing from string works")
    end
  end

  def test_naptr
    update = Update.new
    update.add('example.com.','NAPTR', 3600, '1 0 "s" "SIP+D2T" "" _sip._tcp.example.com.')
    update.encode
  end
end
