control 'AMZL-02-720260' do
  title 'The Amazon Linux 2 operating system security patches and updates must be installed and up to
    date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of
    information technology (IT) systems. However, failure to keep operating system and application software patched is a
    common mistake made by IT professionals. New patches are released daily, and it is often difficult for even
    experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system
    exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches
    and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The
    lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Verify the operating system security patches and updates are installed and up to date. 
Check that the available package security updates have been installed on the system with the following command:

# yum history list | more
Loaded plugins: langpacks, product-id, subscription-manager
ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    70 | install aide             | 2016-05-05 10:58 | Install       |     1
    69 | update -y                | 2016-05-04 14:34 | Update     |   18 EE
    68 | install vlc                | 2016-04-21 17:12 | Install        |   21
    67 | update -y                | 2016-04-21 17:04 | Update     |     7 EE
    66 | update -y                | 2016-04-15 16:47 | E, I, U         |   84 EE

If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding.'

  desc 'fix', 'Install the operating system patches or updated packages as local policy dictates.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-720260'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['packages']
  tag 'host'
  tag 'container'

  if input('disconnected_system')
    describe "The system is set to a `disconnected` state and you must validate
                the state of the system packages manually" do
      skip "The system is set to a `disconnected` state and you must validate
        the state of the system packages manually, or through another process, if you
        have an established update and patch process, please set this control as
        `Not Applicable` with a `caevat` via an overlay."
    end
  else
    updates = linux_update.updates
    package_names = updates.map { |h| h['name'] }

    describe.one do
      describe 'List of out-of-date packages' do
        subject { package_names }
        it { should be_empty }
      end

      updates.each do |update|
        describe package(update['name']) do
          its('version') { should eq update['version'] }
        end
      end
    end
  end
end
