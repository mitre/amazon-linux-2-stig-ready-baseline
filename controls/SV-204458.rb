control 'AMZL-02-720250' do
  title 'The Amazon Linux 2 operating system must be a vendor supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches
    for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the
    system software.'
  desc 'check', 'Verify the version of the operating system is vendor supported.
    Check the version of the operating system with the following command:
    # cat /etc/system-releasecat /etc/system-release-cpe
    cpe:2.3:o:amazon:amazon_linux:2
    If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-720250'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['supported_release']
  tag 'host'
  tag 'container'

  describe "Manually review that the release is not supported by the vendor" do
    skip "Manually review that the release is not supported by the vendor"
  end
end
