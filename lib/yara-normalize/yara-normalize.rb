require 'digest/sha1'

module Yara
	class Rule < Struct.new(:name, :tags, :meta, :strings, :condition)
		def hash_code
			normalized_strings = strings.map{|x| x.gsub(/^\s*\$\w+\s*=\s*/,'')}.sort.join("%")
			strings_hash = Digest::SHA1.hexdigest(normalized_strings)
			condition_hash = Digest::SHA1.hexdigest(normalized_condition)
			#pp normalized_strings
			#pp normalized_condition
			"#{strings_hash}#{condition_hash}"
		end
		
		def condition_var_replace(condition)
			vars = {}
			nextvar = 'a'
			condition.gsub(/\$\w+/) do |x|
				unless vars[x]
					vars[x] = "\$#{nextvar}"
					nextvar = (nextvar[0] + 1).chr
				end
				vars[x]
			end
		end
		
		# ($a and $b) or ($c and $d and ($e or $f)) => (($e or $f) and $c and $d) or ($a and $b)
		# [['$a','and','$b'],'or',['$c','and','$d','and',['$e','or','$f']]]
		def normalized_condition
			return condition if condition =~ /(any of them|all of them|any \d+ of them)/i
			condition_var_replace(condition_rearrange(condition_var_replace(self.condition)).join(","))
		end
		
		def condition_rearrange(condition)
			c = condition.gsub(/\(/,'[').gsub(/\)/,'],').gsub(/((\$\w+|and|or|not))/) do |x| "'#{x}',"; end.gsub(/,\]/,']').gsub(/,\s*$/,'')
			arr = eval("[#{c}]")
			condition_rearrange2(arr)
		end
		
		def condition_rearrange2(subpart)
			if subpart.is_a? Array
				subpart.sort {|a,b| 
					if a.is_a? Array and b.is_a? Array
						b.flatten.length <=> a.flatten.length
					elsif a.is_a? Array
						-1
					elsif b.is_a? Array
						1
					else
						b.length <=> a.length
					end
				}.map{ |sp|
					condition_rearrange2(sp)
				}
			else
				subpart
			end
		end
	end
	
	class Normalizer
		def initialize
		end
		
		def normalize(rule)
			raise "Invalid rule: rules must begin with the word 'rule'" unless rule =~ /^\s*rule\s/
			raise "Invalid rule: rules must end with a closing bracket, }" unless rule =~ /\}\s*$/
			if rule =~ /^\s*rule\s+(\w+)(\s*:\s*(\w[\w\s]+\w))?\s*\{\s*meta:\s*(.*?)\s*strings:\s*(.*?)\s*condition:\s*(.*?)\s*\}\s*$/m
				#pp $~.captures
				name,_,tags,meta,strings,condition = $~.captures
				tags = tags.split(/\s+/) if tags
				metatags = {}
				meta.split(/\n+/).each do |x|
					a,b = x.split(/\s*=\s*/)
					metatags[a.strip] = b.strip
				end
				strings = strings.split(/\n+/).map{|x| x.strip}
				condition = condition.strip
				Rule.new(name,tags,metatags,strings,condition)
			else
				nil
			end
		end
	end
end