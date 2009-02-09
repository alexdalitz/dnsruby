require 'Dnsruby'

# e.g. ruby trace_dns.rb example.com

res = Dnsruby::Recursor.new


res.recursion_callback=(Proc.new { |packet|
	
	packet.additional.each { |a| print a.to_s + "\n" }
	
	print(";; Received #{packet.answersize} bytes from #{packet.answerfrom}\n\n")
})


res.query_dorecursion(ARGV[0])
