require 'digest'

module YaraTools
  # Hash format version embedded in every yn-hash identifier.
  # Increment when the normalization algorithm changes so consumers can
  # detect that two hashes are not directly comparable (e.g. yn01 vs yn02).
  VERSION = "02"

  class YaraRule
    attr_reader :original, :name, :tags, :meta, :strings, :condition, :normalized_strings

    def initialize(ruletext)
      # Normalize line endings and strip single-line (//) comments before
      # any further parsing so they never appear in meta/strings/condition.
      ruletext = ruletext.gsub(/[\r\n]+/, "\n").gsub(/^\s*\/\/.*$/, '')
      @original = ruletext

      # Lookup table used by _normalize_condition to replace variable names
      # ($foo, #foo) with stable positional tokens ($0, $1, …) so that
      # cosmetic renames do not affect the normalized condition hash.
      @lookup_table = {}
      @next_replacement = 0

      # Single-pass regex parse.  The rule grammar is:
      #   rule <name> [: <tags>] { [meta: …] strings: … condition: … }
      # The .*? quantifiers are non-greedy so they stop at the first matching
      # delimiter keyword rather than consuming the whole file.
      rule_re = /rule\s+([\w\-]+)(\s*:\s*(\w[\w\s]+\w))?\s*\{\s*(meta:\s*(.*?))?strings:\s*(.*?)\s*condition:\s*(.*?)\s*\}/m
      if ruletext =~ rule_re
        name, _, tags, _, meta, strings, condition = $~.captures

        @name = name

        # Tags are optional; split on whitespace/commas when present.
        @tags = tags.strip.split(/[,\s]+/) if tags

        # Parse the meta section into a key/value Hash.  Each line has the
        # form: key = value (value may contain spaces and quotes).
        @meta = {}
        if meta
          meta.split(/\n/).each do |m|
            k, v = m.strip.split(/\s*=\s*/, 2)
            @meta[k] = v if v
          end
        end

        # Parse the strings section, normalizing whitespace around '=' and
        # canonicalizing any hex byte strings (e.g. { 4D 5A } → { 4d 5a }).
        @normalized_strings = []
        @strings = strings.split(/\n/).map do |s|
          s = s.strip

          # Collapse any amount of whitespace around '=' to a single ' = '.
          s[/\s*=\s*/, 0] = " = " if s[/\s*=\s*/, 0]

          # Hex byte strings: normalise spacing and case so that
          # { 4D5A } and { 4d 5a } produce the same output.
          if s =~ /= \{([0-9a-fA-F\s]+)\}/
            hexstr = $1.gsub(/\s+/, '').downcase.scan(/../).join(" ")
            s = s.gsub(/= \{([0-9a-fA-F\s]+)\}/, "= { #{hexstr} }")
          end

          # Collect only the value portion (right of ' = ') for hashing,
          # so that variable renames ($a → $b) do not change the hash.
          _, val = s.split(/ = /, 2)
          @normalized_strings << (val || s)
          s
        end
        @normalized_strings.sort!

        @condition = condition.split(/\n/).map(&:strip)
        @normalized_condition = @condition.map { |x| _normalize_condition(x) }
      end
    end

    # Replace named variable references in a condition line with positional
    # tokens so that renaming $mshtmlExec_1 → $a does not change the hash.
    # Both count (#) and match ($) sigils are preserved.
    # NOTE: This method is intentionally prefixed with _ to signal that it is
    # an internal implementation detail; do not call it from outside this class.
    def _normalize_condition(condition)
      condition.gsub(/[\$\#]\w+/) do |x|
        key = x[1, 1000]
        @lookup_table[key] ||= begin
          val = @next_replacement.to_s
          @next_replacement += 1
          val
        end
        x[0].chr + @lookup_table[key]
      end
    end

    # Return a canonical, human-readable rendering of the rule with
    # consistent indentation and ordering.  Tags, meta, strings, and
    # condition are preserved in their original order.
    def normalize
      text = "rule #{@name} "
      text += ": #{@tags.join(' ')} " if @tags && !@tags.empty?
      text += "{\n"

      if @meta && !@meta.empty?
        text += "  meta:\n"
        @meta.each { |k, v| text += "    #{k} = #{v}\n" }
      end

      if @strings && !@strings.empty?
        text += "  strings:\n"
        @strings.each { |s| text += "    #{s}\n" if s =~ /\w/ }
      end

      if @condition && !@condition.empty?
        text += "  condition:\n"
        @condition.each { |c| text += "    #{c}\n" if c =~ /\w/ }
      end

      text + "}"
    end

    # Return a stable identifier for this rule in the form:
    #   yn<VERSION>:<strings_fingerprint>:<condition_fingerprint>
    #
    # The strings fingerprint is the last 16 hex chars of the SHA-256 digest
    # of the sorted, normalised string values joined by '%'.
    # The condition fingerprint is the last 10 hex chars of the SHA-256 digest
    # of the normalised condition lines joined by '%'.
    #
    # Using SHA-256 (replacing the previous MD5) gives 256-bit collision
    # resistance and avoids MD5's well-known preimage and collision weaknesses.
    #
    # SECURITY NOTE: This method is named `hash` to match the public API, but
    # it overrides Ruby's built-in Object#hash, which is expected to return an
    # Integer for use as a Hash table key.  Do NOT use YaraRule objects as Hash
    # keys; use .hash (this method) only for YARA rule fingerprinting.
    def hash
      normalized_strings   = @normalized_strings.join("%")
      normalized_condition = @normalized_condition.join("%")
      strings_digest   = Digest::SHA256.hexdigest(normalized_strings)
      condition_digest = Digest::SHA256.hexdigest(normalized_condition)
      "yn#{VERSION}:#{strings_digest[-16, 16]}:#{condition_digest[-10, 10]}"
    end
  end

  # Splits a multi-rule YARA file into individual YaraRule objects.
  class Splitter
    # Parse a string containing one or more YARA rules and return an Array of
    # YaraRule instances, one per rule found in +ruleset+.
    def self.split(ruleset)
      # Strip line endings and single-line comments before scanning so that
      # comment text cannot interfere with the rule boundary regex.
      clean = ruleset.gsub(/[\r\n]+/, "\n").gsub(/^\s*\/\/.*$/, '')
      rule_re = /(rule\s+([\w\-]+)(\s*:\s*(\w[\w\s]+\w))?\s*\{\s*(meta:\s*(.*?))?strings:\s*(.*?)\s*condition:\s*(.*?)\s*\})/m
      clean.scan(rule_re).map { |rule| YaraRule.new(rule[0]) }
    end
  end
end
