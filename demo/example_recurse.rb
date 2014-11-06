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

# Example usage for Net::DNS::Resolver::Recurse
# Performs recursion for a query.

require 'dnsruby'

res = Dnsruby::Recursor.new
Dnsruby::TheLog.level = Logger::DEBUG
name, type, klass = ARGV
type  ||= "A"
klass ||= "IN"
res.hints=("198.41.0.4") # A.ROOT-SERVER.NET.
packet = res.query(name, type, klass)
print packet.to_s
