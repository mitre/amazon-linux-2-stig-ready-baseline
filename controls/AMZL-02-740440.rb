control 'AMZL-02-740440' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH daemon does not permit
    Kerberos authentication unless needed.'
  desc "Kerberos authentication for SSH is often implemented using Generic Security Service Application Program
    Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's
    Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to
    exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be
    disabled for systems not using this capability."
  desc 'check', 'Verify the SSH daemon does not permit Kerberos to authenticate passwords unless approved.
    Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:
    # grep -i kerberosauth /etc/ssh/sshd_config
    KerberosAuthentication no
    If the "KerberosAuthentication" keyword is missing, or is set to "yes" and is not documented with the Information
    System Security Officer (ISSO), or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "KerberosAuthentication" keyword in "/etc/ssh/sshd_config" (this file may be named
    differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and
    set the value to "no":
    KerberosAuthentication no
    The SSH service must be restarted for changes to take effect.
    If Kerberos authentication is required, it must be documented, to include the location of the configuration file,
    with the ISSO.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag stig_id: 'AMZL-02-740440'
  tag cci: ['CCI-000318', 'CCI-000368', 'CCI-001812', 'CCI-001813', 'CCI-001814']
  tag nist: ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1)', 'CM-5 (1) (a)']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized AMZN' do
      skip 'Control not applicable - SSH is not installed within containerized AMZN'
    end
  else
    describe sshd_config do
      its('KerberosAuthentication') { should cmp 'no' }
    end
  end
end
