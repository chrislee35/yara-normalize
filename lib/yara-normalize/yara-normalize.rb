require 'digest/md5'
require 'pp'
module YaraTools
	VERSION = "01"
	class YaraRule
		attr_reader :original, :name, :tags, :meta, :strings, :condition, :normalized_strings
		def initialize(ruletext)
			ruletext = ruletext.gsub(/[\r\n]+/,"\n").gsub(/^\s*\/\/.*$/,'')
			@original = ruletext
			@lookup_table = {}
			@next_replacement = 0
			
			if ruletext =~ /rule\s+([\w\-]+)(\s*:\s*(\w[\w\s]+\w))?\s*\{\s*(meta:\s*(.*?))?strings:\s*(.*?)\s*condition:\s*(.*?)\s*\}/m
				name,_,tags,_,meta,strings,condition = $~.captures
				@name = name
				@tags = tags.strip.split(/[,\s]+/) if tags
				@meta = {}
				meta.split(/\n/).each do |m|
					k,v = m.strip.split(/\s*=\s*/,2)
					if v
						@meta[k] = v
					end
				end
				@normalized_strings = []
				@strings = strings.split(/\n/).map do |s|
					# strip off the spaces from the edges and then replace the first = with ' = '.
					s = s.strip
					if s[/\s*=\s*/,0]
						s[/\s*=\s*/,0] = " = "
					end
					if s =~ /= \{([0-9a-fA-F\s]+)\}/
						# normalize the hex string
						hexstr = $1.gsub(/\s+/,'').downcase.scan(/../).join(" ")
						s = s.gsub(/= \{([0-9a-fA-F\s]+)\}/, "= { #{hexstr} }")
					end
					_, val = s.split(/ = /,2)
					if val
						@normalized_strings << val
					else
						@normalized_strings << s
					end
					s
				end
				@normalized_strings.sort!
				@condition = condition.split(/\n/).map{|x| x.strip}
				@normalized_condition = @condition.map{|x| _normalize_condition(x)}
			end
		end
		
		def _normalize_condition(condition)
			condition.gsub(/[\$\#]\w+/) do |x|
				key = x[1,1000]
				if not @lookup_table[key]
					@lookup_table[key] = @next_replacement.to_s
					@next_replacement += 1
				end
				x[0].chr+@lookup_table[key]
			end
		end
		
		def normalize
			text = "rule #{@name} "
			if @tags and @tags.length > 0
				text += ": #{@tags.join(' ')} "
			end
			text += "{\n"
			if @meta and @meta.length > 0
				text += "  meta:\n"
				@meta.each do |k,v|
					text += "    #{k} = #{v}\n"
				end
			end
			if @strings and @strings.length > 0
				text += "  strings:\n"
				@strings.each do |s|
					if s =~ /\w/
						text += "    #{s}\n"
					end
				end
			end
			if @condition and @condition.length > 0
				text += "  condition:\n"
				@condition.each do |c|
					if c =~ /\w/
						text += "    #{c}\n"
					end
				end
			end
			text + "}"
		end
		
		def hash
			normalized_strings = @normalized_strings.join("%")
			normalized_condition = @normalized_condition.join("%")
			strings_hash = Digest::MD5.hexdigest(normalized_strings)
			condition_hash = Digest::MD5.hexdigest(normalized_condition)
			"yn#{VERSION}:#{strings_hash[-16,16]}:#{condition_hash[-10,10]}"
		end
	end
	
	class Splitter
		def Splitter.split(ruleset)
			ruleset.gsub(/[\r\n]+/,"\n").gsub(/^\s*\/\/.*$/,'').scan(/(rule\s+([\w\-]+)(\s*:\s*(\w[\w\s]+\w))?\s*\{\s*(meta:\s*(.*?))?strings:\s*(.*?)\s*condition:\s*(.*?)\s*\})/m).map do |rule|
				YaraRule.new(rule[0])
			end
		end
	end
end
