control 'AMZL-02-710320' do
  title 'The Amazon Linux 2 operating system must be configured to lock accounts for a minimum of 15
    minutes after three unsuccessful logon attempts within a 15-minute timeframe.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password
    guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Check that the system locks an account for a minimum of 15 minutes after three unsuccessful logon
    attempts within a period of 15 minutes with the following command:
    # grep pam_faillock.so /etc/pam.d/password-auth
    auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
    auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
    account required pam_faillock.so
    If the "deny" parameter is set to "0" or a value greater than "3" on both "auth" lines with the "pam_faillock.so"
    module, or is missing from these lines, this is a finding.
    If the "even_deny_root" parameter is not set on both "auth" lines with the "pam_faillock.so" module, or is missing
    from these lines, this is a finding.
    If the "fail_interval" parameter is set to "0" or is set to a value less than "900" on both "auth" lines with the
    "pam_faillock.so" module, or is missing from these lines, this is a finding.
    If the "unlock_time" parameter is not set to "0", "never", or is set to a value less than "900" on both "auth" lines
    with the "pam_faillock.so" module, or is missing from these lines, this is a finding.
    Note: The maximum configurable value for "unlock_time" is "604800".
    If any line referencing the "pam_faillock.so" module is commented out, this is a finding.
    # grep pam_faillock.so /etc/pam.d/system-auth
    auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
    auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
    account required pam_faillock.so
    If the "deny" parameter is set to "0" or a value greater than "3" on both "auth" lines with the "pam_faillock.so"
    module, or is missing from these lines, this is a finding.
    If the "even_deny_root" parameter is not set on both "auth" lines with the "pam_faillock.so" module, or is missing
    from these lines, this is a finding.
    If the "fail_interval" parameter is set to "0" or is set to a value less than "900" on both "auth" lines with the
    "pam_faillock.so" module, or is missing from these lines, this is a finding.
    If the "unlock_time" parameter is not set to "0", "never", or is set to a value less than "900" on both "auth" lines
    with the "pam_faillock.so" module or is missing from these lines, this is a finding.
    Note: The maximum configurable value for "unlock_time" is "604800".
    If any line referencing the "pam_faillock.so" module is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to lock an account for the maximum period when three unsuccessful logon attempts in 15 minutes are made.

Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines:

auth        required      pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth        sufficient    pam_unix.so try_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account     required      pam_faillock.so

Note: Per requirement AMZL-02-710199, Amazon Linux 2 must be configured to not overwrite custom authentication configuration settings while using the authconfig utility, otherwise manual changes to the listed files will be overwritten whenever the authconfig utility is used.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag stig_id: 'AMZL-02-710320'
  tag cci: ['CCI-000044', 'CCI-002236', 'CCI-002237', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b', 'AC-7 b', 'AC-7 b']
  tag subsystems: ['pam', 'faillock']
  tag 'host'
  tag 'container'

  # pam rules files to check
  pa_rules = pam('/etc/pam.d/password-auth').lines
  sa_rules = pam('/etc/pam.d/system-auth').lines

  # rule patterns to match for
  faillock_rule_pattern = 'auth [default=die]|required pam_faillock.so'
  deny_pattern = faillock_rule_pattern + " deny=#{input('unsuccessful_attempts')}"
  fail_interval_pattern = faillock_rule_pattern + " fail_interval=#{input('fail_interval')}"
  unlock_time_pattern = faillock_rule_pattern + " unlock_time=(0|never|#{input('lockout_time')})"

  # explicit rulesets to look for
  req = input('required_rules')
  alt = input('alternate_rules')

  describe.one do
    describe 'pam rules for the faillock module' do
      it 'should exactly match an appropriately configured ruleset in password-auth' do
        expect(pa_rules).to match_pam_rules(req).exactly, "missing required rules: #{req.select { |rule| !pa_rules.include?(rule) }}"
      end
    end
    describe 'pam rules for the faillock module' do
      it 'should exactly match an appropriately configured ruleset in password-auth' do
        expect(pa_rules).to match_pam_rules(alt).exactly, "missing alternate rules: #{alt.select { |rule| !pa_rules.include?(rule) }}"
      end
    end
  end

  describe 'pam rules for the faillock module' do
    it 'should have the expected settings enabled in password-auth' do
      expect(pa_rules).to match_pam_rule(deny_pattern), "missing: #{deny_pattern}"
      expect(pa_rules).to match_pam_rule(fail_interval_pattern), "missing: #{fail_interval_pattern}"
      expect(pa_rules).to match_pam_rule(unlock_time_pattern), 'missing or misconfigured unlock_time'
    end
  end

  describe.one do
    describe 'pam rules for the faillock module' do
      it 'should exactly match an appropriately configured ruleset in system-auth' do
        expect(sa_rules).to match_pam_rules(req).exactly, "missing required rules: #{req.select { |rule| !sa_rules.include?(rule) }}"
      end
    end
    describe 'pam rules for the faillock module' do
      it 'should exactly match an appropriately configured ruleset in system-auth' do
        expect(sa_rules).to match_pam_rules(alt).exactly, "missing alternate rules: #{alt.select { |rule| !sa_rules.include?(rule) }}"
      end
    end
  end

  describe 'pam rules for the faillock module' do
    it 'should have the expected settings enabled in system-auth' do
      expect(sa_rules).to match_pam_rule(deny_pattern), "missing: #{deny_pattern}"
      expect(sa_rules).to match_pam_rule(fail_interval_pattern), "missing: #{fail_interval_pattern}"
      expect(sa_rules).to match_pam_rule(unlock_time_pattern), 'missing or misconfigured unlock_time'
    end
  end
end
