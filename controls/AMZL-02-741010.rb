control 'AMZL-02-741010' do
  title 'The Amazon Linux 2 operating system must be configured so that all wireless network adapters are
    disabled.'
  desc "The use of wireless networking can introduce many different attack vectors into the organization's network.
    Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless
    access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor
    and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to
    create a denial of service to valid network resources."
  desc 'check', 'Verify that there are no wireless interfaces configured on the system.
    This is N/A for systems that do not have wireless network adapters.
    Check for the presence of active wireless interfaces with the following command:
    # nmcli device
    DEVICE TYPE STATE
    eth0 ethernet connected
    wlp3s0 wifi disconnected
    lo loopback unmanaged
    If a wireless interface is configured and its use on the system is not documented with the Information System
    Security Officer (ISSO), this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces with the following command:
    #nmcli radio wifi off'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000424-GPOS-00188'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000481-GPOS-000481']
  tag stig_id: 'AMZL-02-741010'
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
  tag subsystems: ['network', 'wifi', 'nmcli']
  tag 'host'
  tag 'container'

  describe command('nmcli device') do
    its('stdout.strip') { should_not match(/wifi connected/) }
  end
end
