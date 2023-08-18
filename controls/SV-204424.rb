control 'AMZL-02-710290' do
  title 'The Amazon Linux 2 operating system must not allow accounts configured with blank or null
    passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that
    account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:
    # grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth
    If this produces any output, it may be possible to log on with accounts with empty passwords.
    If null passwords can be used, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.

Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" to prevent logons with empty passwords.

Note: Per requirement AMZL-02-710199, Amazon Linux 2 must be configured to not overwrite custom authentication configuration settings while using the authconfig utility, otherwise manual changes to the listed files will be overwritten whenever the authconfig utility is used.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-710290'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['pam', 'password']
  tag 'host'
  tag 'container'

  describe pam('/etc/pam.d/system-auth') do
    its('lines') { should_not match_pam_rule('.* .* pam_unix.so nullok') }
  end
  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should_not match_pam_rule('.* .* pam_unix.so nullok') }
  end
end
