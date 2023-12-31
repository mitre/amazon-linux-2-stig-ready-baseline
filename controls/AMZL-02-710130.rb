control 'AMZL-02-710130' do
  title 'The Amazon Linux 2 operating system must be configured so that when passwords are changed or new
    passwords are established, the new password must contain at least one lower-case character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password.
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing
    and brute-force attacks.
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex
    the password, the greater the number of possible combinations that need to be tested before the password is
    compromised.'
  desc 'check', 'Note: The value to require a number of lower-case characters to be set is expressed as a negative
    number in "/etc/security/pwquality.conf".
    Check the value for "lcredit" in "/etc/security/pwquality.conf" with the following command:
    # grep lcredit /etc/security/pwquality.conf
    lcredit = -1
    If the value of "lcredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the system to require at least one lower-case character when creating or changing a
    password.
    Add or modify the following line
    in "/etc/security/pwquality.conf":
    lcredit = -1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag stig_id: 'AMZL-02-710130'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
  tag subsystems: ['pwquality', 'password']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('lcredit') { should cmp < 0 }
  end
end
