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

begin
require 'test/tc_single_resolver'
rescue LoadError
  require 'tc_single_resolver'
end
begin
require 'test/tc_soak_base'
rescue LoadError
  require 'tc_soak_base'
end
include Dnsruby
# This class tries to soak test the Dnsruby library.
# It can't do this very well, owing to the small number of sockets allowed to be open simultaneously.
# @TODO@ Future versions of dnsruby will allow random streaming over a fixed number of (cycling) random sockets,
# so this test can be beefed up considerably at that point.
# @todo@ A test DNS server running on localhost is really needed here
class TestSingleResolverSoak < Minitest::Test

  def test_many_asynchronous_queries_one_single_resolver
    run_many_asynch_queries_test_single_res(1)
  end

  def test_many_asynchronous_queries_many_single_resolvers
    run_many_asynch_queries_test_single_res(50)
  end

  def run_many_asynch_queries_test_single_res(num_resolvers)
    q = Queue.new
    resolvers = []
    timed_out = 0
    query_count = 0
    num_resolvers.times do |n|
      resolvers.push(SingleResolver.new)
      resolvers[n].packet_timeout=4
    end
    res_pos = 0
    start = Time.now
    #  @todo@ On windows, MAX_FILES is 256. This means that we have to limit
    #  this test while we're not using single sockets.
    #  We run four queries per iteration, so we're limited to 64 runs.
    63.times do |i|
      rr_count = 0
      TestSoakBase::Rrs.each do |data|
        rr_count+=1
        res = resolvers[res_pos]
        res_pos=+1
        if (res_pos >= num_resolvers)
          res_pos = 0
        end
        res.send_async(Message.new(data[:name], data[:type]), q, [i,rr_count])
        #         p "Sent #{i}, #{rr_count}, Queue #{q}"
        query_count+=1
      end
    end
    query_count.times do |i|
      id,ret, error = q.pop
      if (error.class == ResolvTimeout)
        timed_out+=1
      elsif (ret.class != Message)
        p "ERROR RETURNED : #{error}"
      end

    end
    stop=Time.now
    time_taken=stop-start
    p "Query count : #{query_count}, #{timed_out} timed out. #{time_taken} time taken"
    assert(timed_out < query_count * 0.1, "#{timed_out} of #{query_count} timed out!")
  end


  def test_many_threads_on_one_single_resolver_synchronous
    #  Test multi-threaded behaviour
    #  Check the header IDs to make sure they're all different
    threads = Array.new
    res = SingleResolver.new
    ids = []
    mutex = Mutex.new
    timed_out = 0
    query_count = 0
    res.packet_timeout=4
    start=Time.now
    #  Windows limits us to 256 sockets
    num_times=250
    if (/java/ =~ RUBY_PLATFORM)
      #  JRuby threads are native threads, so let's not go too mad!
      num_times=50
    end
    num_times.times do |i|
      threads[i] = Thread.new{
        40.times do |j|
          TestSoakBase::Rrs.each do |data|
            mutex.synchronize do
              query_count+=1
            end
            packet=nil
            begin
              packet = res.query(data[:name], data[:type])
            rescue ResolvTimeout
              mutex.synchronize {
                timed_out+=1
              }
              next
            end
            assert(packet)
            ids.push(packet.header.id)
            assert_equal(packet.question[0].qclass,    'IN',             'Class correct'           )
          end
        end
      }
    end
    threads.each do |thread|
      thread.join
    end
    stop=Time.now
    time_taken=stop-start
    p "Query count : #{query_count}, #{timed_out} timed out. #{time_taken} time taken"
    #     check_ids(ids) # only do this if we expect all different IDs - e.g. if we stream over a single socket
    assert(timed_out < query_count * 0.1, "#{timed_out} of #{query_count} timed out!")
  end

  def check_ids(ids)
    ids.sort!
    count = 0
    ids.each do |id|
      count+=1
      if (count < ids.length-1)
        assert(ids[count+1] != id, "Two identical header ids used!")
      end
    end
  end

  def test_many_threads_on_many_single_resolvers
    #  Test multi-threaded behaviour
    #  @todo@ Check the header IDs to make sure they're all different
    threads = Array.new
    mutex = Mutex.new
    timed_out = 0
    query_count = 0
    start=Time.now
    num_times=250
    if (/java/ =~ RUBY_PLATFORM)
      #  JRuby threads are native threads, so let's not go too mad!
      num_times=50
    end
    num_times.times do |i|
      threads[i] = Thread.new{
        res = SingleResolver.new
        res.packet_timeout=4
        40.times do |j|
          TestSoakBase::Rrs.each do |data|
            mutex.synchronize do
              query_count+=1
            end
            q = Queue.new
            res.send_async(Message.new(data[:name], data[:type]), q, [i,j])
            id, packet, error = q.pop
            if (error.class == ResolvTimeout)
              mutex.synchronize {
                timed_out+=1
              }
              next
            elsif (packet.class!=Message)
              p "ERROR! #{error}"
            end

            assert(packet)
            assert_equal(packet.question[0].qclass,    'IN',             'Class correct'           )
          end
        end
      }
    end
    threads.each do |thread|
      thread.join
    end
    stop=Time.now
    time_taken=stop-start
    p "Query count : #{query_count}, #{timed_out} timed out. #{time_taken} time taken"
    assert(timed_out < query_count * 0.1, "#{timed_out} of #{query_count} timed out!")
  end


end