control 'AMZL-02-720010' do
  title 'The Amazon Linux 2 operating system must not have the ypserv package installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or
    NIS+ services.'
  desc 'check', 'The NIS service provides an unencrypted authentication service that does not provide for the
    confidentiality and integrity of user passwords or the remote session.
    Check to see if the "ypserve" package is installed with the following command:
    # yum list installed ypserv
    If the "ypserv" package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities by removing the "ypserv" package
    from the system with the following command:
    # yum remove ypserv'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag stig_id: 'AMZL-02-720010'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag subsystems: ['packages']
  tag 'host'
  tag 'container'

  describe package('ypserv') do
    it { should_not be_installed }
  end
end
