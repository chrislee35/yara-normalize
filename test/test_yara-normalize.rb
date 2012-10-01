require 'helper'
class TestYaraNormalize < Test::Unit::TestCase
	should "normalize a simple signature" do
		sig =<<EOS
rule newIE0daymshtmlExec
{
	meta:
		author = "adnan.shukor@gmail.com"
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
		yn = Yara::Normalizer.new
		nrm = yn.normalize(sig)
		hash = {}
		nrm.members.sort.each do |member|
			hash[member] = nrm[member]
		end
		assert_equal({"condition"=>
		  "($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))",
		 "tags"=>nil,
		 "name"=>"newIE0daymshtmlExec",
		 "strings"=>
		  ["$mshtmlExec_1 = /document.execCommand(['\"]selectAll['\"])/ nocase fullword",
		   "$mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword",
		   "$mshtmlExec_3 = /<body on(load|select)=['\"]w*?();['\"] on(load|select)=['\"]w*?()['\"]/ nocase",
		   "$mshtmlExec_4 = /var w{1,} = new Array()/ nocase",
		   "$mshtmlExec_5 = /window.document.createElement(['\"]img['\"])/ nocase",
		   "$mshtmlExec_6 = /w{1,}[0][['\"]src['\"]] = ['\"]w{1,}['\"]/ nocase",
		   "$mshtmlExec_7 = /<iframe src=['\"].*?['\"]/ nocase"],
		 "meta"=>
		  {"author"=>"\"adnan.shukor@gmail.com\"",
		   "description"=>"\"Internet Explorer CMshtmlEd::Exec() 0day\"",
		   "ref"=>
		    "\"http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/\"",
		   "impact"=>"4",
		   "hide"=>"false",
		   "cve"=>"\"CVE-2012-XXXX\"",
		   "version"=>"\"1\""}}, hash)
		assert_equal("ee2e32d623a0debca271cada22b35b3b904d6abd678cf2a48a87b43cd6302e73f67510c19ffe2f1a", nrm.hash_code)
	end

	should "normalize a simple signature with tags and spaces instead of tabs" do
		sig =<<EOS
rule newIE0daymshtmlExec : tag1 tag2 tag3
{
  meta:
    author = "adnan.shukor@gmail.com"
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
		yn = Yara::Normalizer.new
		nrm = yn.normalize(sig)
		hash = {}
		nrm.members.sort.each do |member|
			hash[member] = nrm[member]
		end
		assert_equal({"condition"=>
		  "($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3) or ($mshtmlExec_4 and $mshtmlExec_5 and ($mshtmlExec_6 or $mshtmlExec_7))",
		 "tags"=>["tag1","tag2","tag3"],
		 "name"=>"newIE0daymshtmlExec",
		 "strings"=>
		  ["$mshtmlExec_1 = /document.execCommand(['\"]selectAll['\"])/ nocase fullword",
		   "$mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword",
		   "$mshtmlExec_3 = /<body on(load|select)=['\"]w*?();['\"] on(load|select)=['\"]w*?()['\"]/ nocase",
		   "$mshtmlExec_4 = /var w{1,} = new Array()/ nocase",
		   "$mshtmlExec_5 = /window.document.createElement(['\"]img['\"])/ nocase",
		   "$mshtmlExec_6 = /w{1,}[0][['\"]src['\"]] = ['\"]w{1,}['\"]/ nocase",
		   "$mshtmlExec_7 = /<iframe src=['\"].*?['\"]/ nocase"],
		 "meta"=>
		  {"author"=>"\"adnan.shukor@gmail.com\"",
		   "description"=>"\"Internet Explorer CMshtmlEd::Exec() 0day\"",
		   "ref"=>
		    "\"http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/\"",
		   "impact"=>"4",
		   "hide"=>"false",
		   "cve"=>"\"CVE-2012-XXXX\"",
		   "version"=>"\"1\""}}, hash)
		assert_equal("ee2e32d623a0debca271cada22b35b3b904d6abd678cf2a48a87b43cd6302e73f67510c19ffe2f1a", nrm.hash_code)
	end

	should "normalize a simple signature that has been rearranged" do
		sig =<<EOS
rule newIE0daymshtmlExec
{
  meta:
    author = "adnan.shukor@gmail.com"
    ref = "http://blog.vulnhunt.com/index.php/2012/09/17/ie-execcommand-fuction-use-after-free-vulnerability-0day_en/"
    description = "Internet Explorer CMshtmlEd::Exec() 0day"
    cve = "CVE-2012-XXXX"
    version = "1"
    impact = 4
    hide = false
  strings:
    $mshtmlExec_3 = /\<body\son(load|select)=['"]\w*?\(\)\;['"]\son(load|select)=['"]\w*?\(\)['"]/ nocase
    $mshtmlExec_5 = /window\.document\.createElement\(['"]img['"]\)/ nocase
    $mshtmlExec_6 = /\w{1,}\[0\]\[['"]src['"]\]\s\=\s['"]\w{1,}['"]/ nocase
    $mshtmlExec_4 = /var\s\w{1,}\s=\snew\sArray\(\)/ nocase
    $mshtmlExec_1 = /document\.execCommand\(['"]selectAll['"]\)/ nocase fullword
    $mshtmlExec_7 = /\<iframe\ssrc=['"].*?['"]/ nocase
    $mshtmlExec_2 = /YMjf\\u0c08\\u0c0cKDogjsiIejengNEkoPDjfiJDIWUAzdfghjAAuUFGGBSIPPPUDFJKSOQJGH/ nocase fullword
  condition:
    ($mshtmlExec_4 and ($mshtmlExec_6 or $mshtmlExec_7) and $mshtmlExec_5) or ($mshtmlExec_1 and $mshtmlExec_2 and $mshtmlExec_3)
}
EOS
		yn = Yara::Normalizer.new
		nrm = yn.normalize(sig)
		assert_equal("ee2e32d623a0debca271cada22b35b3b904d6abd678cf2a48a87b43cd6302e73f67510c19ffe2f1a", nrm.hash_code)
	end
	
	should "normalize a simple signature that has been rearranged" do
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
		yn = Yara::Normalizer.new
		nrm = yn.normalize(sig)
		hash = {}
		nrm.members.sort.each do |member|
			hash[member] = nrm[member]
		end
		assert_equal({"tags"=>["IntegerParsing", "DataConversion"],
		 "name"=>"DataConversion__wide",
		 "condition"=>"any of them",
		 "strings"=>
		  ["$ = \"wtoi\" nocase",
		   "$ = \"wtol\" nocase",
		   "$ = \"wtof\" nocase",
		   "$ = \"wtodb\" nocase"],
		 "meta"=>{"weight"=>"1"}},hash)
		assert_equal("dacfb7f79e2ad96cb66c4784323d91e09e8ad2f8c214c8ea0a52e3a3bda71e6612f02361609e0f7a", nrm.hash_code)
	end
end

