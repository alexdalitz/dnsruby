# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

class TestAxfr < Minitest::Test
  def test_axfr
    zt = Dnsruby::ZoneTransfer.new
    zt.transfer_type = Dnsruby::Types.AXFR
    zt.server = "ns0.validation-test-servers.nominet.org.uk"
    zone = zt.transfer("validation-test-servers.nominet.org.uk")
    assert(zone.length > 0)
    assert(zt.last_tsigstate==nil)
  end


  #  NB - test_ixfr is in tc_tsig.rg - this is becuase it requires
  #  TSIG to make an update (which we can then test for with ixfr)
end