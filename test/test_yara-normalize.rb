require 'helper'
require 'pp'

class TestYaraNormalize < Test::Unit::TestCase
	should "normalize a simple signature" do
		sig =<<EOS
rule newIE0daymshtmlExec
{
	meta:
		author = "redacted @ gmail.com"
		ref = "http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/"
		description = "Internet Explorer CMshtmlEd::Exec() 0day"
		cve = "CVE-2012-XXXX"
		version = "1"
		impact = 4
		hide = false
	strings:
		$mshtmlExec_1 = /document\.execCommand\(['"]selectAll['"]\)/ nocase fullword
		$mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword
		$mshtmlExec_3 = /\<body\son(load|select)=['"]\w*?\(\)\;['"]\son(load|select)=['"]\w*?\(\)['"]/ nocase
		$mshtmlExec_4 = /var\s\w{1,}\s=\snew\sArray\(\)/ nocase
		$mshtmlExec_5 = /window\.document\.createElement\(['"]img['"]\)/ nocase
		$mshtmlExec_6 = /\w{1,}\[0\]\[['"]src['"]\]\s\=\s['"]\w{1,}['"]/ nocase
		$mshtmlExec_7 = /\<iframe\ssrc=['"].*?['"]/ nocase
	condition:
		($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))
}
EOS
		yn = YaraTools::YaraRule.new(sig)
		assert_equal("yn01:3c0de1ad64681376:3ff75e9945", yn.hash)
		assert_equal("newIE0daymshtmlExec", yn.name)
		assert_equal("\"redacted @ gmail.com\"", yn.meta['author'])
		assert_equal(["$mshtmlExec_1 = /document.execCommand(['\"]selectAll['\"])/ nocase fullword",
		 "$mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword",
		 "$mshtmlExec_3 = /<body on(load|select)=['\"]w*?();['\"] on(load|select)=['\"]w*?()['\"]/ nocase",
		 "$mshtmlExec_4 = /var w{1,} = new Array()/ nocase",
		 "$mshtmlExec_5 = /window.document.createElement(['\"]img['\"])/ nocase",
		 "$mshtmlExec_6 = /w{1,}[0][['\"]src['\"]] = ['\"]w{1,}['\"]/ nocase",
		 "$mshtmlExec_7 = /<iframe src=['\"].*?['\"]/ nocase"], yn.strings)
		assert_equal(
			["($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))"], 
			yn.condition
		)
		hash1 = yn.hash
		sig =<<EOS
rule newIE0daymshtmlExec : tag1 tag2 tag3
{
  meta:
    author = "redacted @ gmail.com"
    ref = "http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/"
    description = "Internet Explorer CMshtmlEd::Exec() 0day"
    cve = "CVE-2012-XXXX"
    version = "1"
    impact = 4
    hide = false
  strings:
    $mshtmlExec_1 = /document\.execCommand\(['"]selectAll['"]\)/ nocase fullword
    $mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword
    $mshtmlExec_3 = /\<body\son(load|select)=['"]\w*?\(\)\;['"]\son(load|select)=['"]\w*?\(\)['"]/ nocase
    $mshtmlExec_4 = /var\s\w{1,}\s=\snew\sArray\(\)/ nocase
    $mshtmlExec_5 = /window\.document\.createElement\(['"]img['"]\)/ nocase
    $mshtmlExec_6 = /\w{1,}\[0\]\[['"]src['"]\]\s\=\s['"]\w{1,}['"]/ nocase
    $mshtmlExec_7 = /\<iframe\ssrc=['"].*?['"]/ nocase
  condition:
    ($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))
}
EOS
		yn = YaraTools::YaraRule.new(sig)
		assert_equal(hash1, yn.hash)
		assert_equal("newIE0daymshtmlExec", yn.name)
		assert_equal(["tag1","tag2","tag3"], yn.tags)
		assert_equal("\"redacted @ gmail.com\"", yn.meta['author'])
		assert_equal(["$mshtmlExec_1 = /document.execCommand(['\"]selectAll['\"])/ nocase fullword",
		 "$mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword",
		 "$mshtmlExec_3 = /<body on(load|select)=['\"]w*?();['\"] on(load|select)=['\"]w*?()['\"]/ nocase",
		 "$mshtmlExec_4 = /var w{1,} = new Array()/ nocase",
		 "$mshtmlExec_5 = /window.document.createElement(['\"]img['\"])/ nocase",
		 "$mshtmlExec_6 = /w{1,}[0][['\"]src['\"]] = ['\"]w{1,}['\"]/ nocase",
		 "$mshtmlExec_7 = /<iframe src=['\"].*?['\"]/ nocase"], yn.strings)
		assert_equal(
			["($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))"], 
			yn.condition
		)
	end
	
	should "normalize a simple signature that has a condition of 'any of them'" do
		sig =<<EOS
rule DataConversion__wide : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "wtoi" nocase
		$ = "wtol" nocase
		$ = "wtof" nocase
		$ = "wtodb" nocase
	condition:
		any of them
}
EOS
		yn = YaraTools::YaraRule.new(sig)
		assert_equal("yn01:488085c947cb22ed:d936fceffe", yn.hash)
		assert_equal("1", yn.meta['weight'])
		assert_equal("DataConversion__wide", yn.name)
		assert_equal(["IntegerParsing", "DataConversion"], yn.tags)
		assert_equal(["$ = \"wtoi\" nocase",
		 "$ = \"wtol\" nocase",
		 "$ = \"wtof\" nocase",
		 "$ = \"wtodb\" nocase"], yn.strings)
		assert_equal(["any of them"], yn.condition)
	end
end

